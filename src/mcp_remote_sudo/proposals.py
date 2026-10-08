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
    allow, warnings = [], []
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
        for p in op.params:
            if p.name not in args:
                warnings.append(f"{name}.{p.name} is unconstrained")
        if op.mutating:
            warnings.append(f"{name} is a mutating operation")
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
    return manifest, warnings


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


def read_for_grant(state_dir: str | Path, proposal_id: str, expected_sha256: str) -> dict[str, Any]:
    """Read the proposal once, verify the digest of exactly those bytes, and parse those same bytes."""
    if not PROPOSAL_ID.fullmatch(proposal_id or ""):
        raise ProposalError("invalid proposal id")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or ""):
        raise ProposalError("--sha256 must be a 64-character lowercase hex digest")
    path = proposals_dir(state_dir) / f"{proposal_id}.yaml"
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ProposalError(f"cannot read proposal {proposal_id}: {exc}") from exc
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        raise ProposalError(f"proposal {proposal_id} changed since review (sha256 {actual} != {expected_sha256})")
    manifest = yaml.safe_load(data)
    if not isinstance(manifest, dict):
        raise ProposalError("proposal is not a mapping")
    return manifest
