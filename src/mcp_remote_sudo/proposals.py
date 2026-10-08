"""Authority proposals: the agent drafts, the operator grants.

``authority.propose`` renders a TaskAuthority from installed packs (their templates' default constraints plus any
constraints the caller supplies), validates it, stores it under ``<state>/proposals/<id>.yaml`` and returns the YAML,
a diff against the active authority and its SHA-256. It grants nothing: expansion stays prohibited. The operator
applies it with ``mcp-remote-sudo-admin grant --proposal <id> --sha256 <digest>``, which checks the digest against
the bytes it reads, so a proposal changed after review is refused.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import secrets
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from .authority import Authority
from .packs import Registry

PROPOSAL_ID = re.compile(r"^prop-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$")
MAX_OPERATIONS = 50
MAX_PROPOSALS = 100
MIN_TTL, MAX_TTL = 5, 24 * 60
STANDARD_DENY = ["shell.exec", "package.install", "filesystem.write", "system.reboot"]


class ProposalError(ValueError):
    pass


def _render(manifest: dict[str, Any]) -> list[str]:
    return yaml.safe_dump(manifest, sort_keys=False, default_flow_style=False).splitlines(keepends=True)


def diff_text(current: Authority | None, new: Authority) -> str:
    before = _render(current.manifest) if current else []
    out = "".join(difflib.unified_diff(before, _render(new.manifest), "active", "proposed"))
    old_tools = current.allowed_tools if current else set()
    added, removed = sorted(new.allowed_tools - old_tools), sorted(old_tools - new.allowed_tools)
    return out + f"\noperations added: {added or 'none'}\noperations removed: {removed or 'none'}\n"


def proposals_dir(state_dir: str | Path) -> Path:
    return Path(state_dir) / "proposals"


def template_constraints(registry: Registry, operation: str) -> dict[str, Any]:
    """Default constraints for an operation from its pack's templates (first template that mentions it)."""
    pack = registry.packs[registry.pack_of(operation)]
    for template in pack.templates.values():
        rules = template.get("rules", {})
        if operation in rules:
            return json.loads(json.dumps(rules[operation]))
    return {}


def _widens(template: Any, caller: Any) -> bool:
    """Whether a caller's constraint admits anything the template's constraint would reject."""
    if not isinstance(template, dict):
        return caller != template
    if not isinstance(caller, dict):
        # An exact value widens unless the template itself would accept it (same matcher as authorization).
        return not Authority._args_match({"v": caller}, {"v": template})
    if "enum" in template and ("enum" not in caller or not set(map(repr, caller["enum"])) <= set(map(repr, template["enum"]))):
        return True
    if "minimum" in template and ("minimum" not in caller or caller["minimum"] < template["minimum"]):
        return True
    if "maximum" in template and ("maximum" not in caller or caller["maximum"] > template["maximum"]):
        return True
    return False


def review_warnings(manifest: dict[str, Any], registry: Registry) -> list[str]:
    """What an operator should weigh before granting: computed from the manifest itself (so the admin can recompute it
    from the verified bytes instead of trusting what the agent relayed)."""
    warnings = []
    for rule in manifest.get("allow", []):
        name, args = rule.get("tool"), rule.get("args") or {}
        op = registry.operations.get(name)
        if op is None:
            warnings.append(f"{name} is not a built-in operation (the service checks installed packs at reload)"); continue
        if op.mutating:
            warnings.append(f"{name} is a mutating operation (confirmation: {rule.get('confirmation', 'operator')})")
        for p in op.params:
            spec = args.get(p.name)
            kinds = {t for t in (getattr(p.type, "__args__", None) or (p.type,)) if t is not type(None)}
            scalar = bool(kinds) and kinds <= {str, int, float, bool}
            numeric = bool(kinds) and kinds <= {int, float}   # Optional[int] counts too
            if spec is None:
                if scalar and not op.needs_runtime:   # only parameters the constraint grammar can meaningfully bound
                    warnings.append(f"{name}.{p.name} is unconstrained")
            elif isinstance(spec, dict) and numeric and "enum" not in spec and ("minimum" not in spec or "maximum" not in spec):
                warnings.append(f"{name}.{p.name} has a one-sided bound {spec}")
            if spec is not None:
                template = template_constraints(registry, name).get(p.name)
                if template is not None and _widens(template, spec):
                    warnings.append(f"{name}.{p.name} = {spec} widens the pack template ({template})")
    return warnings


def render(*, registry: Registry, active: Authority, purpose: str, operations: list[str],
           constraints: dict[str, dict[str, Any]] | None, ttl_minutes: int,
           now: datetime | None = None) -> tuple[dict[str, Any], list[str]]:
    if not isinstance(purpose, str) or not purpose.strip() or len(purpose) > 200:
        raise ProposalError("purpose must be 1-200 characters")
    if not isinstance(operations, list) or not operations or len(operations) > MAX_OPERATIONS:
        raise ProposalError(f"operations must be a list of 1-{MAX_OPERATIONS} operation names")
    if not isinstance(ttl_minutes, int) or isinstance(ttl_minutes, bool) or not MIN_TTL <= ttl_minutes <= MAX_TTL:
        raise ProposalError(f"ttl_minutes must be between {MIN_TTL} and {MAX_TTL}")
    constraints = constraints or {}
    if not isinstance(constraints, dict):
        raise ProposalError("constraints must map operation -> {argument: constraint}")
    unknown = sorted(set(operations) - set(registry.operations))
    if unknown:
        raise ProposalError(f"no installed pack provides: {unknown}")
    stray = sorted(set(constraints) - set(operations))
    if stray:
        raise ProposalError(f"constraints given for operations not proposed: {stray}")
    now = now or datetime.now(timezone.utc)
    allow = []
    if "authority.propose" in active.allowed_tools and "authority.propose" not in operations \
            and "authority.propose" in registry.operations:
        operations = [*operations, "authority.propose"]   # keep the agent able to ask for the next change
    for name in sorted(set(operations)):
        op = registry.operations[name]
        args = template_constraints(registry, name)
        extra = constraints.get(name, {})
        if not isinstance(extra, dict):
            raise ProposalError(f"constraints for {name} must be a mapping")
        bad = sorted(set(extra) - {p.name for p in op.params})
        if bad:
            raise ProposalError(f"{name} has no arguments {bad}")
        args.update(extra)
        allow.append({"tool": name, **({"args": args} if args else {})})
    binding = dict(active.manifest["binding"])
    manifest = {
        "apiVersion": "mcp-remote-sudo/v1", "kind": "TaskAuthority",
        "metadata": {"id": f"proposal-{now.strftime('%Y%m%dT%H%M%SZ')}", "version": 1, "purpose": purpose.strip()},
        "binding": binding,
        "lifetime": {"notAfter": (now + timedelta(minutes=ttl_minutes)).replace(microsecond=0).isoformat(),
                     "renewable": False, "expansion": "prohibited"},
        "allow": allow,
        "deny": [{"tool": t} for t in STANDARD_DENY if t not in registry.operations],
        "receipts": {"required": True},
    }
    Authority(manifest)  # validates (fails closed on any malformed constraint)
    return manifest, review_warnings(manifest, registry)


def store(state_dir: str | Path, manifest: dict[str, Any], *, now: datetime | None = None) -> tuple[str, Path, str]:
    now = now or datetime.now(timezone.utc)
    pid = f"prop-{now.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}"
    directory = proposals_dir(state_dir); directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    data = yaml.safe_dump(manifest, sort_keys=False).encode()
    path = directory / f"{pid}.yaml"
    tmp = directory / f".{pid}.tmp"
    tmp.write_bytes(data); tmp.chmod(0o640); os.replace(tmp, path)
    for old in sorted(directory.glob("prop-*.yaml"))[:-MAX_PROPOSALS]:
        old.unlink(missing_ok=True)
    return pid, path, hashlib.sha256(data).hexdigest()


MAX_PROPOSAL_BYTES = 256 * 1024


def read_for_grant(state_dir: str | Path, proposal_id: str, expected_sha256: str) -> dict[str, Any]:
    """Read the proposal once, verify the digest of exactly those bytes, and parse those same bytes.
    The proposals directory is writable by the unprivileged service and this runs as root: refuse symlinks (directory
    or file), anything but a regular file, and oversized files."""
    if not PROPOSAL_ID.fullmatch(proposal_id or ""):
        raise ProposalError("invalid proposal id")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or ""):
        raise ProposalError("--sha256 must be a 64-character lowercase hex digest")
    directory = proposals_dir(state_dir)
    try:
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise ProposalError(f"{directory} is not a plain directory") from None
    try:
        fd = os.open(f"{proposal_id}.yaml", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except OSError as exc:
        raise ProposalError(f"cannot open proposal {proposal_id}: {exc.strerror}") from exc
    finally:
        os.close(dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ProposalError(f"proposal {proposal_id} is not a regular file")
        if st.st_size > MAX_PROPOSAL_BYTES:
            raise ProposalError(f"proposal {proposal_id} is too large")
        data = os.read(fd, MAX_PROPOSAL_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_PROPOSAL_BYTES or hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ProposalError(f"proposal {proposal_id} changed since review (digest mismatch)")
    manifest = yaml.safe_load(data)
    if not isinstance(manifest, dict):
        raise ProposalError("proposal is not a mapping")
    return manifest
