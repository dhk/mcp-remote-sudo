"""Installing external Task Packs safely (run by the operator as root via mcp-remote-sudo-admin).

Threat model: the operator runs this as root, so nothing from a pack may execute here.
- Wheels only, every distribution pinned and hashed, no dependency resolution (no build hooks, no surprises).
- Installed with ``pip --target`` into a non-site directory (wheel ``.pth`` files are never executed).
- Never replaces mcp-remote-sudo or its runtime dependencies, and never shadows the standard library, the core
  virtualenv, or another pack (the service appends the packs directory at lowest priority as a second layer).
- Pack code is never imported here; only distribution metadata is read.
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import sys
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Callable, Iterable, Sequence

PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.+!_-]*)$")
HASH = re.compile(r"^--hash=sha256:[0-9a-f]{64}$")


class PackInstallError(RuntimeError):
    pass


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class Pinned:
    name: str
    version: str
    hashes: tuple[str, ...]


def parse_lockfile(text: str) -> list[Pinned]:
    """Accept only `name==version --hash=sha256:<64 hex>`... lines (backslash continuations allowed)."""
    logical, buf = [], ""
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip() if not raw.lstrip().startswith("#") else ""
        if line.endswith("\\"):
            buf += line[:-1] + " "; continue
        buf += line
        if buf.strip(): logical.append(buf.strip())
        buf = ""
    if buf.strip(): logical.append(buf.strip())
    pins = []
    for entry in logical:
        tokens = entry.split()
        m = PIN.fullmatch(tokens[0])
        if not m:
            raise PackInstallError(f"not an exact pin (name==version): {tokens[0]!r}")
        hashes = tuple(tokens[1:])
        if not hashes or not all(HASH.fullmatch(h) for h in hashes):
            raise PackInstallError(f"{tokens[0]}: every requirement needs only --hash=sha256:<digest> options")
        pins.append(Pinned(canonical(m.group(1)), m.group(2), hashes))
    if not pins:
        raise PackInstallError("lockfile has no requirements")
    names = [p.name for p in pins]
    if len(set(names)) != len(names):
        raise PackInstallError("lockfile pins a distribution more than once")
    return pins


def protected_distributions(root: str = "mcp-remote-sudo") -> set[str]:
    """mcp-remote-sudo and its transitive runtime dependencies, as installed in the core environment."""
    seen: set[str] = set(); todo = [root]
    while todo:
        name = canonical(todo.pop())
        if name in seen: continue
        seen.add(name)
        try: requires = metadata.requires(name) or []
        except metadata.PackageNotFoundError: continue
        for req in requires:
            if "extra ==" in req: continue
            todo.append(re.split(r"[\s;<>=!~\[(]", req, 1)[0])
    return seen


def top_level_names(dist: metadata.Distribution) -> set[str]:
    text = dist.read_text("top_level.txt")
    if text:
        return {n.strip() for n in text.split() if n.strip()}
    names = set()
    for f in dist.files or []:
        first = f.parts[0]
        if first.endswith((".dist-info", ".data")) or first == "..": continue
        names.add(first[:-3] if first.endswith(".py") else first)
    return names


def environment_top_levels(paths: Sequence[str] | None = None, *, exclude: Iterable[str] = ()) -> dict[str, str]:
    """top-level import name -> distribution, for the distributions installed at `paths` (default: sys.path)."""
    skip = {canonical(e) for e in exclude}; owners: dict[str, str] = {}
    for dist in metadata.distributions(path=list(paths) if paths is not None else None):
        name = canonical(dist.metadata["Name"] or "")
        if name in skip: continue
        for top in top_level_names(dist): owners.setdefault(top, name)
    return owners


def _resolvable_in_core(top: str, packs_dir: Path) -> bool:
    """Whether `top` already resolves on the core sys.path (catches editable installs and modules without metadata).
    find_spec on a top-level name locates it without executing its code; the packs dir is never on the admin's path."""
    if not top.isidentifier(): return False
    try: spec = importlib.util.find_spec(top)
    except (ImportError, ValueError): return True   # fail closed on anything odd
    if spec is None: return False
    origin = Path(spec.origin).resolve() if spec.origin and spec.origin not in ("built-in", "frozen") else None
    return not (origin and packs_dir.resolve() in origin.parents)


def check_staged(staging: Path, pins: list[Pinned], packs_dir: Path) -> list[metadata.Distribution]:
    staged = list(metadata.distributions(path=[str(staging)]))
    got = {canonical(d.metadata["Name"]): d for d in staged}
    if set(got) != {p.name for p in pins}:
        raise PackInstallError(f"pip installed {sorted(got)}, lockfile pins {sorted(p.name for p in pins)}")
    protected = protected_distributions() | {"pip", "setuptools", "wheel"}
    clash = sorted(set(got) & protected)
    if clash:
        raise PackInstallError(f"refusing to replace mcp-remote-sudo or its dependencies: {clash}")
    core = environment_top_levels([p for p in sys.path if p and Path(p).resolve() != packs_dir.resolve()])
    others = environment_top_levels([str(packs_dir)], exclude=got) if packs_dir.exists() else {}
    for name, dist in got.items():
        for top in top_level_names(dist):
            if top in sys.stdlib_module_names:
                raise PackInstallError(f"{name}: top-level name {top!r} shadows the standard library")
            if top in core:
                raise PackInstallError(f"{name}: top-level name {top!r} collides with {core[top]} in the core environment")
            if _resolvable_in_core(top, packs_dir):
                raise PackInstallError(f"{name}: top-level name {top!r} is already importable in the core environment")
            if top in others:
                raise PackInstallError(f"{name}: top-level name {top!r} collides with installed pack {others[top]}")
    return staged


def remove_distribution_files(packs_dir: Path, dist_name: str) -> bool:
    for info in sorted(packs_dir.glob("*.dist-info")):
        dist = metadata.PathDistribution(info)
        if canonical(dist.metadata["Name"] or "") != canonical(dist_name): continue
        for top in top_level_names(dist):
            target = packs_dir / top
            if target.is_dir() and not target.is_symlink(): shutil.rmtree(target)
            for candidate in (target, packs_dir / f"{top}.py"):
                if candidate.is_file() or candidate.is_symlink(): candidate.unlink()
        shutil.rmtree(info)
        return True
    return False


def install(lockfile: Path, packs_dir: Path, run: Callable[[Sequence[str]], object], python: str = sys.executable) -> list[str]:
    pins = parse_lockfile(lockfile.read_text())
    packs_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    staging = packs_dir.with_name(f".{packs_dir.name}.staging-{os.getpid()}")
    shutil.rmtree(staging, ignore_errors=True)
    try:
        result = run([python, "-I", "-m", "pip", "install", "--no-input", "--disable-pip-version-check",
                      "--only-binary", ":all:", "--require-hashes", "--no-deps", "--no-compile",
                      "--target", str(staging), "-r", str(lockfile)])
        if getattr(result, "returncode", 1) != 0:
            raise PackInstallError(f"pip failed: {getattr(result, 'stderr', '').strip()[-500:]}")
        staged = check_staged(staging, pins, packs_dir)
        installed = []
        for dist in staged:
            name = canonical(dist.metadata["Name"])
            remove_distribution_files(packs_dir, name)   # upgrade in place
            installed.append(f"{name}=={dist.version}")
        for entry in staging.iterdir():
            os.replace(entry, packs_dir / entry.name)
        return installed
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def installed(packs_dir: Path) -> list[dict]:
    if not packs_dir.exists(): return []
    out = []
    for dist in sorted(metadata.distributions(path=[str(packs_dir)]), key=lambda d: canonical(d.metadata["Name"])):
        eps = [ep.name for ep in dist.entry_points if ep.group == "mcp_remote_sudo.packs"]
        out.append({"distribution": canonical(dist.metadata["Name"]), "version": dist.version, "entry_points": eps})
    return out
