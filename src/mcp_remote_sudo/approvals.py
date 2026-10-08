"""Per-action operator approval for mutating operations (#42, ``confirmation: operator``).

Flow:
1. The service records a *pending* request (``<state>/pending/<id>.json``: operation, arguments, manifest hash) and
   tells the agent to wait. The pending store is writable by the service, so it is only a display aid.
2. The operator runs ``mcp-remote-sudo-admin approve <id>`` (root). The admin shows exactly what will run and, on
   confirmation, writes a root-only approval record (``/var/lib/mcp-remote-sudo-approvals/<id>.json``) binding the
   request ID, operation, arguments and manifest hash, valid for a few minutes.
3. The agent retries with the request ID. The root helper atomically *consumes* the record (rename, read, unlink)
   and dispatches only if every bound field matches and it has not expired. One approval, one execution: code
   running as the service user can neither forge nor replay an approval.
"""
from __future__ import annotations

import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

REQUEST_ID = re.compile(r"^req-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
APPROVALS_DIR = "/var/lib/mcp-remote-sudo-approvals"
APPROVAL_TTL = timedelta(minutes=10)


class ApprovalError(ValueError):
    pass


def new_request_id(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return f"req-{now.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"


def _check_id(request_id: str) -> str:
    if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
        raise ApprovalError("invalid request id")
    return request_id


def _atomic_json(path: Path, payload: dict[str, Any], mode: int) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, sort_keys=True); fh.flush(); os.fsync(fh.fileno())
    os.replace(tmp, path)


def write_pending(state_dir: str | Path, request_id: str, operation: str, arguments: dict, manifest_hash: str) -> Path:
    directory = Path(state_dir) / "pending"; directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    path = directory / f"{_check_id(request_id)}.json"
    _atomic_json(path, {"request_id": request_id, "operation": operation, "arguments": arguments,
                        "manifest_hash": manifest_hash, "created": datetime.now(timezone.utc).isoformat()}, 0o640)
    return path


def read_pending(state_dir: str | Path, request_id: str) -> dict[str, Any]:
    path = Path(state_dir) / "pending" / f"{_check_id(request_id)}.json"
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise ApprovalError(f"no pending request {request_id}") from exc
    if not isinstance(data, dict) or data.get("request_id") != request_id:
        raise ApprovalError(f"pending request {request_id} is malformed")
    if not isinstance(data.get("operation"), str) or not isinstance(data.get("arguments"), dict):
        raise ApprovalError(f"pending request {request_id} is malformed")
    return data


def approve(approvals_dir: str | Path, request_id: str, operation: str, arguments: dict, manifest_hash: str,
            *, now: datetime | None = None, ttl: timedelta = APPROVAL_TTL) -> Path:
    """Root-only: write the single-use approval record the helper will consume."""
    now = now or datetime.now(timezone.utc)
    directory = Path(approvals_dir); directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / f"{_check_id(request_id)}.json"
    if path.exists():
        raise ApprovalError(f"{request_id} is already approved and not yet used")
    _atomic_json(path, {"request_id": request_id, "operation": operation, "arguments": arguments,
                        "manifest_hash": manifest_hash, "not_after": (now + ttl).isoformat()}, 0o600)
    return path


def consume(approvals_dir: str | Path, request_id: str, operation: str, arguments: dict, manifest_hash: str,
            *, now: datetime | None = None) -> None:
    """Helper-side: atomically take the approval (so it can never be used twice), then check every bound field."""
    now = now or datetime.now(timezone.utc)
    directory = Path(approvals_dir)
    path = directory / f"{_check_id(request_id)}.json"
    taken = directory / f".consumed-{request_id}-{os.getpid()}-{secrets.token_hex(4)}"
    try:
        os.rename(path, taken)          # atomic: exactly one consumer wins
    except FileNotFoundError:
        raise ApprovalError("operator_approval_missing") from None
    try:
        record = json.loads(taken.read_text())
    except (OSError, ValueError):
        raise ApprovalError("operator_approval_malformed") from None
    finally:
        taken.unlink(missing_ok=True)
    expected = {"request_id": request_id, "operation": operation, "arguments": arguments, "manifest_hash": manifest_hash}
    if any(record.get(k) != v for k, v in expected.items()):
        raise ApprovalError("operator_approval_mismatch")
    try:
        expired = datetime.fromisoformat(record["not_after"]) <= now
    except (KeyError, TypeError, ValueError):
        raise ApprovalError("operator_approval_malformed") from None
    if expired:
        raise ApprovalError("operator_approval_expired")
