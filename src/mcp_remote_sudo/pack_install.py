"""Installing external Task Packs safely (run by the operator as root via mcp-remote-sudo-admin).

Threat model: the operator runs this as root, so nothing from a pack may execute here, and nothing a wheel claims
about itself may decide which paths get written or deleted.

Layout: one directory per distribution, ``<packs_dir>/<canonical-name>/`` (a ``pip --target`` tree). The service
appends each to ``sys.path`` at lowest priority. Consequences:
- removal deletes exactly ``<packs_dir>/<name>`` — never a path derived from wheel metadata;
- collision checks run on the files actually staged, not on what ``top_level.txt`` claims;
- no shared directories between distributions (``bin/`` etc.), so an install can't clobber another pack;
- installs are transactional: stage and check everything, then swap directories by rename, keeping the previous
  version until the caller confirms the service loaded the new one (``Transaction.commit`` / ``rollback``).

Other rules: wheels only, every distribution pinned and hashed, no dependency resolution (no build hooks); never
replace mcp-remote-sudo or its runtime dependencies; never import pack code here.
"""
from __future__ import annotations

import fcntl
import importlib.machinery
import importlib.util
import os
import re
import shutil
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Callable, Iterable, Sequence

PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.+!_-]*)$")
HASH = re.compile(r"^--hash=sha256:[0-9a-f]{64}$")
IGNORED_ENTRIES = {"bin", "__pycache__"}   # per-distribution tree: scripts can't collide with another pack


class PackInstallError(RuntimeError):
    pass


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class Pinned:
    name: str
    version: str
    hashes: tuple[str, ...]

    def requirement_line(self) -> str:
        return f"{self.name}=={self.version} " + " ".join(self.hashes) + "\n"


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


def _requires(dist: metadata.Distribution) -> list[str]:
    out = []
    for req in dist.requires or []:
        if "extra ==" in req: continue
        out.append(canonical(re.split(r"[\s;<>=!~\[(]", req, 1)[0]))
    return out


def protected_distributions(root: str = "mcp-remote-sudo") -> set[str]:
    """mcp-remote-sudo and its transitive runtime dependencies, as installed in the core environment."""
    seen: set[str] = set(); todo = [root]
    while todo:
        name = canonical(todo.pop())
        if name in seen: continue
        seen.add(name)
        try: todo.extend(_requires(metadata.distribution(name)))
        except metadata.PackageNotFoundError: continue
    return seen


def actual_entries(tree: Path) -> set[str]:
    """Top-level importable names actually present in a --target tree (not what metadata claims)."""
    names = set()
    for e in tree.iterdir():
        if e.name.endswith((".dist-info", ".data")) or e.name in IGNORED_ENTRIES: continue
        names.add(e.name)
    return names


LIBS_DIR = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\.libs$")   # auditwheel-vendored shared libraries (e.g. pillow.libs)


def _module_name(entry: str) -> str | None:
    """The importable top-level name for a staged entry, or None if it isn't a plain module/package/extension."""
    for suffix in sorted(importlib.machinery.EXTENSION_SUFFIXES, key=len, reverse=True):   # e.g. _cffi_backend.cpython-312-x86_64-linux-gnu.so
        if entry.endswith(suffix) and entry[:-len(suffix)].isidentifier():
            return entry[:-len(suffix)]
    if entry.endswith(".py") and entry[:-3].isidentifier():
        return entry[:-3]
    return entry if entry.isidentifier() else None


@contextmanager
def locked(packs_dir: Path):
    """Exclusive lock over the packs directory for a whole install/remove (incl. restart confirmation).
    Yields the list of distributions recovered from an interrupted run (see ``recover``)."""
    packs_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    with open(packs_dir / ".lock", "a") as fh:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise PackInstallError("another pack install/remove is in progress") from None
        yield recover(packs_dir)


JOURNAL_LINE = re.compile(r"^(new|replace) ([a-z0-9][a-z0-9-]*)$")


def _read_journal(previous: Path) -> list[tuple[str, str]]:
    journal = previous / ".journal"
    if not journal.is_file(): return []
    return [m.groups() for m in (JOURNAL_LINE.fullmatch(l.strip()) for l in journal.read_text().splitlines()) if m]


def undo(packs_dir: Path, previous: Path) -> list[str]:
    """Idempotently return every journaled name to its pre-run state. Safe to repeat after a partial run:
    - replace + backup present  -> restore the backup over whatever is there;
    - replace + no backup       -> leave it (never moved aside, or already restored);
    - new                       -> remove the target if present."""
    undone = []
    for kind, name in _read_journal(previous):
        target, backup = packs_dir / name, previous / name
        if target.is_symlink() or backup.is_symlink(): continue
        if kind == "replace" and backup.is_dir():
            if target.exists(): shutil.rmtree(target)
            os.replace(backup, target); undone.append(name)
        elif kind == "new" and target.exists():
            shutil.rmtree(target); undone.append(name)
    return undone


def recover(packs_dir: Path) -> list[str]:
    """Undo an interrupted run (caller holds the lock). A surviving ``.previous-<pid>/`` means the run never
    confirmed its new packs; its fsynced ``.journal`` says what to undo. ``.trash-*`` (a retired ``.previous``) and
    ``.staging-*`` are scratch."""
    recovered = []
    for previous in sorted(packs_dir.glob(".previous-*")):
        if previous.is_dir() and not previous.is_symlink():
            recovered += undo(packs_dir, previous)
            _discard(previous)
    for scratch in list(packs_dir.glob(".staging-*")) + list(packs_dir.glob(".trash-*")):
        if scratch.is_dir() and not scratch.is_symlink(): shutil.rmtree(scratch, ignore_errors=True)
    return recovered


def _discard(directory: Path) -> None:
    """Retire a .previous-* atomically (rename) before deleting it, so a half-deleted copy is never 'recovered'."""
    if not directory.exists(): return
    trash = directory.with_name(f".trash-{directory.name.split('-', 1)[-1]}-{os.getpid()}")
    os.replace(directory, trash)
    shutil.rmtree(trash, ignore_errors=True)


def _core_top_levels(exclude: Path) -> set[str]:
    names = set()
    for dist in metadata.distributions(path=[p for p in sys.path if p and not _under(Path(p), exclude)]):
        text = dist.read_text("top_level.txt")
        if text: names.update(n.strip() for n in text.split() if n.strip())
    return names


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve()); return True
    except (ValueError, OSError):
        return False


def _resolvable_in_core(name: str, packs_dir: Path) -> bool:
    """Whether `name` already resolves on the core sys.path (catches editable installs and metadata-less modules).
    find_spec on a top-level name locates it without executing it; the packs dir is never on the admin's path."""
    try: spec = importlib.util.find_spec(name)
    except (ImportError, ValueError): return True   # fail closed
    if spec is None: return False
    origin = spec.origin if spec.origin not in (None, "built-in", "frozen") else None
    return not (origin and _under(Path(origin), packs_dir))


def installed_trees(packs_dir: Path) -> dict[str, Path]:
    if not packs_dir.exists(): return {}
    return {d.name: d for d in sorted(packs_dir.iterdir()) if d.is_dir() and not d.is_symlink() and not d.name.startswith(".")}


def _dist_in(tree: Path) -> metadata.Distribution | None:
    infos = [i for i in tree.glob("*.dist-info") if i.is_dir()]
    return metadata.PathDistribution(infos[0]) if len(infos) == 1 else None


def check_staged(staged: dict[str, Path], packs_dir: Path) -> None:
    protected = protected_distributions() | {"pip", "setuptools", "wheel"}
    clash = sorted(set(staged) & protected)
    if clash:
        raise PackInstallError(f"refusing to replace mcp-remote-sudo or its dependencies: {clash}")
    core = _core_top_levels(packs_dir)
    others = {e: name for name, tree in installed_trees(packs_dir).items() if name not in staged
              for e in actual_entries(tree)}
    seen: dict[str, str] = {}
    for name, tree in staged.items():
        dist = _dist_in(tree)
        if dist is None or canonical(dist.metadata["Name"] or "") != name:
            raise PackInstallError(f"{name}: staging does not contain exactly that one distribution")
        for entry in actual_entries(tree):
            if LIBS_DIR.fullmatch(entry) and (tree / entry).is_dir() and not (tree / entry).is_symlink():
                if entry in others:
                    raise PackInstallError(f"{name}: {entry!r} collides with installed pack {others[entry]}")
                continue   # not importable; only needs to be unique among packs
            mod = _module_name(entry)
            if entry.startswith(".") or mod is None or (tree / entry).is_symlink():
                raise PackInstallError(f"{name}: unexpected top-level entry {entry!r}")
            if mod in sys.stdlib_module_names:
                raise PackInstallError(f"{name}: top-level name {mod!r} shadows the standard library")
            if mod in core or _resolvable_in_core(mod, packs_dir):
                raise PackInstallError(f"{name}: top-level name {mod!r} collides with the core environment")
            if entry in others or mod in {_module_name(o) for o in others}:
                raise PackInstallError(f"{name}: top-level name {mod!r} collides with installed pack {others.get(entry, '?')}")
            if mod in seen:
                raise PackInstallError(f"{name}: top-level name {mod!r} also provided by {seen[mod]}")
            seen[mod] = name


@dataclass
class Transaction:
    """Swapped in; the previous versions and the journal are kept until commit() (or undone by rollback())."""
    packs_dir: Path
    installed: list[str]
    _old: Path

    def commit(self) -> None:
        _discard(self._old)

    def rollback(self) -> None:
        undo(self.packs_dir, self._old)
        _discard(self._old)


def install(lockfile: Path, packs_dir: Path, run: Callable[[Sequence[str]], object], python: str = sys.executable) -> Transaction:
    pins = parse_lockfile(lockfile.read_text())
    packs_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    work = packs_dir / f".staging-{os.getpid()}"
    shutil.rmtree(work, ignore_errors=True); work.mkdir(mode=0o700)
    old = packs_dir / f".previous-{os.getpid()}"
    shutil.rmtree(old, ignore_errors=True)
    try:
        staged: dict[str, Path] = {}
        for pin in pins:
            req = work / f"{pin.name}.req"; req.write_text(pin.requirement_line())
            tree = work / pin.name
            result = run([python, "-I", "-m", "pip", "install", "--no-input", "--disable-pip-version-check",
                          "--only-binary", ":all:", "--require-hashes", "--no-deps", "--no-compile",
                          "--target", str(tree), "-r", str(req)])
            if getattr(result, "returncode", 1) != 0:
                raise PackInstallError(f"pip failed for {pin.name}: {getattr(result, 'stderr', '').strip()[-500:]}")
            staged[pin.name] = tree
        check_staged(staged, packs_dir)
        old.mkdir(mode=0o700)
        for name in staged:
            if (packs_dir / name).is_symlink():
                raise PackInstallError(f"{packs_dir / name} is a symlink; refusing")
        kinds = {name: "replace" if (packs_dir / name).exists() else "new" for name in staged}
        with open(old / ".journal", "w") as fh:   # durable before the first rename: recovery's source of truth
            fh.write("".join(f"{kinds[n]} {n}\n" for n in staged)); fh.flush(); os.fsync(fh.fileno())
        txn = Transaction(packs_dir, [], old)
        try:
            for name, tree in staged.items():
                target = packs_dir / name
                if kinds[name] == "replace": os.replace(target, old / name)
                os.replace(tree, target)
                dist = _dist_in(target)
                txn.installed.append(f"{name}=={dist.version if dist else '?'}")
        except BaseException:   # incl. Ctrl-C between the two renames
            txn.rollback(); raise
        return txn
    finally:
        shutil.rmtree(work, ignore_errors=True)


def dependents(packs_dir: Path, name: str) -> list[str]:
    """Installed packs whose metadata requires `name` (read without importing)."""
    out = []
    for other, tree in installed_trees(packs_dir).items():
        if other == canonical(name): continue
        dist = _dist_in(tree)
        if dist is not None and canonical(name) in _requires(dist):
            out.append(other)
    return out


def remove(packs_dir: Path, name: str) -> bool:
    """Delete exactly <packs_dir>/<canonical name>; never a path derived from wheel metadata."""
    target = packs_dir / canonical(name)
    if not target.exists() or target.is_symlink() or not target.is_dir() or target.parent.resolve() != packs_dir.resolve():
        return False
    trash = packs_dir / f".trash-rm-{target.name}-{os.getpid()}"   # atomic: never leave a half-deleted pack on sys.path
    os.replace(target, trash)
    shutil.rmtree(trash, ignore_errors=True)
    return True


def installed(packs_dir: Path) -> list[dict]:
    out = []
    for name, tree in installed_trees(packs_dir).items():
        dist = _dist_in(tree)
        eps = [ep.name for ep in dist.entry_points if ep.group == "mcp_remote_sudo.packs"] if dist else []
        out.append({"distribution": name, "version": dist.version if dist else None, "entry_points": eps})
    return out


def search_paths(packs_dir: str | Path) -> list[str]:
    """What the service appends to sys.path: one directory per installed distribution."""
    return [str(p) for p in installed_trees(Path(packs_dir)).values()]
