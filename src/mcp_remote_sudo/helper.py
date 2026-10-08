"""mcp-remote-sudo-helper: the root-owned executor for typed privileged operations (#41).

The unprivileged service never holds privilege. When a mutating operation is authorized, the service sends one
bounded JSON request over a Unix socket to this helper, which:

1. accepts connections only from the service user (SO_PEERCRED uid check; the socket is also 0660 root:service);
2. dispatches only operations in its own compiled-in table (``OPERATIONS``) — never anything named by the caller;
3. independently re-checks the active authority manifest (defense in depth: a compromised service still cannot
   invoke an operation or argument the operator's grant does not allow);
4. writes its own root-owned receipt chain.

Started by systemd socket activation (``mcp-remote-sudo-helper.socket``); serves one request per connection.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import pwd
import re
import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import yaml

from . import approvals
from .authority import Authority, ManifestError
from .receipts import ReceiptWriter

SOCKET_PATH = "/run/mcp-remote-sudo/helper.sock"
MAX_REQUEST = 64 * 1024
REQUEST_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
SD_LISTEN_FDS_START = 3
log = logging.getLogger("mcp_remote_sudo.helper")


@dataclass(frozen=True)
class HelperOperation:
    name: str
    run: Callable[..., dict]
    params: dict[str, type]
    confirm: bool = True    # host-changing operations honour the rule's confirmation mode (default: operator)


def _ping() -> dict:
    return {"pong": True}


# The helper's own operation table. Mutation packs (#43) add entries here — never via the request.
OPERATIONS: dict[str, HelperOperation] = {
    "helper.ping": HelperOperation("helper.ping", _ping, {}, confirm=False),
}


class Refused(Exception):
    def __init__(self, reason: str):
        super().__init__(reason); self.reason = reason


def peer_uid(conn: socket.socket) -> int:
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


class Helper:
    def __init__(self, *, manifest: str | Path, receipts: str | Path, allowed_uid: int,
                 operations: dict[str, HelperOperation] | None = None, approvals_dir: str | Path = approvals.APPROVALS_DIR):
        self.manifest = Path(manifest); self.allowed_uid = allowed_uid; self.approvals_dir = Path(approvals_dir)
        self.receipts = ReceiptWriter(receipts); self.operations = operations if operations is not None else OPERATIONS

    def handle(self, raw: bytes, uid: int) -> dict[str, Any]:
        """Validate, authorize and execute one request; every outcome is receipted."""
        request: dict[str, Any] = {}
        authority: Authority | None = None
        try:
            if uid != self.allowed_uid:
                raise Refused("peer_not_service_user")
            if len(raw) > MAX_REQUEST:
                raise Refused("request_too_large")
            try:
                request = json.loads(raw)
            except ValueError:
                raise Refused("invalid_json")
            if not isinstance(request, dict) or set(request) - {"request_id", "operation", "arguments"}:
                raise Refused("invalid_request")
            rid, name, args = request.get("request_id"), request.get("operation"), request.get("arguments", {})
            if not isinstance(rid, str) or not REQUEST_ID.fullmatch(rid):
                raise Refused("invalid_request_id")
            op = self.operations.get(name) if isinstance(name, str) else None
            if op is None:
                raise Refused("operation_not_in_helper_table")
            if not isinstance(args, dict) or set(args) != set(op.params):
                raise Refused("invalid_arguments")
            for key, typ in op.params.items():
                if not isinstance(args[key], typ) or (typ is not bool and isinstance(args[key], bool)):
                    raise Refused("invalid_arguments")
            try:
                authority = Authority.load(self.manifest)
            except (ManifestError, OSError, ValueError, yaml.YAMLError):
                raise Refused("manifest_unavailable")
            decision = authority.evaluate(name, args)
            if not decision.allowed:
                raise Refused(f"manifest:{decision.reason}")
            mode = (decision.rule or {}).get("confirmation", "operator") if op.confirm else "grant-only"
            if mode == "operator":
                # Enforced here, not in the service: a single-use root-owned approval bound to this exact request.
                try:
                    approvals.consume(self.approvals_dir, rid, name, args, authority.manifest_hash)
                except approvals.ApprovalError as exc:
                    raise Refused(str(exc))
        except Refused as exc:
            self._receipt(request, authority, uid, "deny", exc.reason, "denied")
            return {"ok": False, "error": exc.reason}
        try:
            result = op.run(**args)
        except Exception as exc:  # report the class only; adapters must not leak secrets in messages
            self._receipt(request, authority, uid, "allow", "allowed", "failed", error=type(exc).__name__)
            return {"ok": False, "error": f"failed:{type(exc).__name__}"}
        self._receipt(request, authority, uid, "allow", "allowed", "success")
        return {"ok": True, "result": result}

    def _receipt(self, request: dict, authority: Authority | None, uid: int, decision: str, reason: str,
                 result: str, **extra: Any) -> None:
        md = authority.manifest["metadata"] if authority else {}
        self.receipts.write({"component": "helper", "peer_uid": uid,
                             "request_id": request.get("request_id") if isinstance(request, dict) else None,
                             "tool": request.get("operation") if isinstance(request, dict) else None,
                             "arguments": request.get("arguments") if isinstance(request, dict) else None,
                             "manifest_id": md.get("id"), "manifest_hash": authority.manifest_hash if authority else None,
                             "decision": decision, "reason": reason, "result": result, **extra})

    def serve_connection(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(10)
            uid = peer_uid(conn)
            chunks, size = [], 0
            while size <= MAX_REQUEST:
                chunk = conn.recv(4096)
                if not chunk: break
                chunks.append(chunk); size += len(chunk)
                if chunk.endswith(b"\n"): break
            response = self.handle(b"".join(chunks).strip(), uid)
            conn.sendall(json.dumps(response, sort_keys=True).encode() + b"\n")


def call(operation: str, arguments: dict[str, Any], request_id: str, *, path: str = SOCKET_PATH,
         timeout: float = 30.0) -> dict[str, Any]:
    """Client used by the unprivileged service's mutation adapters."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout); s.connect(path)
        s.sendall(json.dumps({"request_id": request_id, "operation": operation, "arguments": arguments}).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk: break
            data += chunk
    return json.loads(data)


def listening_socket(path: str) -> socket.socket:
    """The systemd-activated socket (LISTEN_FDS), or a freshly bound one for development."""
    if os.environ.get("LISTEN_PID") == str(os.getpid()) and int(os.environ.get("LISTEN_FDS", "0")) >= 1:
        return socket.socket(fileno=SD_LISTEN_FDS_START)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    Path(path).unlink(missing_ok=True); sock.bind(path); os.chmod(path, 0o660); sock.listen(8)
    return sock


def main() -> None:
    p = argparse.ArgumentParser(prog="mcp-remote-sudo-helper")
    p.add_argument("--manifest", default="/etc/mcp-remote-sudo/authority.yaml")
    p.add_argument("--receipts", default="/var/log/mcp-remote-sudo-helper/receipts.jsonl")  # root-owned dir: the service user must not be able to unlink it
    p.add_argument("--service-user", default="mcp-remote-sudo")
    p.add_argument("--socket", default=SOCKET_PATH)
    p.add_argument("--approvals-dir", default=approvals.APPROVALS_DIR)
    p.add_argument("--idle-exit", type=float, default=60.0, help="exit after this many idle seconds (socket-activated)")
    a = p.parse_args()
    logging.basicConfig(level=logging.INFO)
    helper = Helper(manifest=a.manifest, receipts=a.receipts, allowed_uid=pwd.getpwnam(a.service_user).pw_uid,
                    approvals_dir=a.approvals_dir)
    sock = listening_socket(a.socket); sock.settimeout(a.idle_exit)
    while True:
        try:
            conn, _ = sock.accept()
        except socket.timeout:
            return  # systemd re-activates on the next connection
        try:
            helper.serve_connection(conn)
        except Exception:
            log.exception("helper connection failed")


if __name__ == "__main__":
    main()
