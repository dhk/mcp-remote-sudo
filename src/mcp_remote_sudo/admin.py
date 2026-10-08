"""mcp-remote-sudo-admin: the operator's surface for authority lifecycle (run with sudo on the host).

The operator, not the agent, changes authority. ``grant`` validates a manifest, checks it against the
installed packs and the service binding, backs up the current authority, installs the new one atomically,
signals the service to reload (SIGHUP, no restart) and confirms the service reports the new manifest hash.
A rejected reload is rolled back automatically.
"""
from __future__ import annotations

import argparse
import difflib
import fcntl
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import yaml

from . import pack_install, packs
from .authority import Authority, ManifestError
from .receipts import verify_chain

DEFAULT_MANIFEST = "/etc/mcp-remote-sudo/authority.yaml"
DEFAULT_STATE_DIR = "/var/lib/mcp-remote-sudo"
DEFAULT_RECEIPTS = "/var/log/mcp-remote-sudo/receipts.jsonl"
DEFAULT_SERVICE = "mcp-remote-sudo.service"
DEFAULT_PACKS_DIR = "/opt/mcp-remote-sudo/packs"


class AdminError(RuntimeError):
    pass


def run(argv: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True, text=True, check=False)


def now() -> datetime:
    return datetime.now(timezone.utc)


def _load(path: str | Path) -> Authority:
    try:
        return Authority.load(path)
    except (ManifestError, OSError, yaml.YAMLError) as exc:
        raise AdminError(f"{path}: {exc}") from exc


def _external_operations(authority: Authority, registry: packs.Registry) -> list[str]:
    """Allowed operations the built-in packs don't provide. The admin runs as root and never imports external
    pack code; the service verifies these against its installed packs at reload (and the grant rolls back if not)."""
    return sorted(authority.allowed_tools - set(registry.operations))


def _expires_in(authority: Authority) -> float:
    return (Authority._parse_time(authority.manifest["lifetime"]["notAfter"]) - now()).total_seconds()


def _render(manifest: dict[str, Any]) -> list[str]:
    return yaml.safe_dump(manifest, sort_keys=False, default_flow_style=False).splitlines(keepends=True)


def diff_text(current: Authority | None, new: Authority) -> str:
    before = _render(current.manifest) if current else []
    out = "".join(difflib.unified_diff(before, _render(new.manifest), "active", "proposed"))
    old_tools = current.allowed_tools if current else set()
    added, removed = sorted(new.allowed_tools - old_tools), sorted(old_tools - new.allowed_tools)
    return out + f"\noperations added: {added or 'none'}\noperations removed: {removed or 'none'}\n"


class Admin:
    def __init__(self, manifest: str, state_dir: str, receipts: str, service: str,
                 registry: packs.Registry | None = None, out=sys.stdout, packs_dir: str = DEFAULT_PACKS_DIR):
        self.manifest = Path(manifest); self.status_path = Path(state_dir) / "authority-status.json"
        self.packs_dir = Path(packs_dir)
        self.receipts = Path(receipts); self.service = service; self.out = out; self.session_mode_override: str | None = None
        # Built-in packs only: importing external pack code as root is exactly what the pack design forbids.
        self.registry = registry or packs.Registry(packs.builtin_packs())

    def say(self, *parts: Any) -> None:
        print(*parts, file=self.out)

    def current(self) -> Authority | None:
        return _load(self.manifest) if self.manifest.exists() else None

    def _session_mode(self) -> str:
        """'manifest' when the service takes its session from the manifest, 'fixed' for a legacy --session service.
        Never guessed: without a readable status file the operator must say which (--session-mode)."""
        if self.session_mode_override:
            return self.session_mode_override
        st = self.read_status()
        mode = (st or {}).get("session_mode")
        if mode in ("manifest", "fixed"):
            return mode
        if st is not None and "session_mode" not in st:
            return "fixed"   # a service from before #39 reports no mode and always runs a fixed session
        raise AdminError(f"cannot determine the service's session mode ({self.status_path} unavailable); "
                         f"pass --session-mode manifest|fixed")

    def read_status(self) -> dict[str, Any] | None:
        try:
            return json.loads(self.status_path.read_text())
        except (OSError, ValueError):
            return None

    # -- commands -----------------------------------------------------------------------------
    def validate(self, path: str) -> Authority:
        a = _load(path)
        remaining = _expires_in(a)
        self.say(f"valid: {a.manifest['metadata']['id']} hash={a.manifest_hash}")
        self.say(f"operations: {sorted(a.allowed_tools)}")
        external = _external_operations(a, self.registry)
        if external:
            self.say(f"not built-in (service verifies against installed packs at grant): {external}")
        self.say(f"notAfter: {a.manifest['lifetime']['notAfter']} ({'EXPIRED' if remaining <= 0 else f'{remaining/3600:.1f}h left'})")
        return a

    def diff(self, path: str) -> None:
        self.out.write(diff_text(self.current(), _load(path)))

    def grant(self, path: str, *, yes: bool = False, timeout: float = 45.0) -> Authority:
        new = _load(path)
        if _expires_in(new) <= 0:
            raise AdminError("refusing to grant an already-expired authority")
        if self._session_mode() == "manifest":
            # Each grant is its own session, so receipts group by investigation.
            m = json.loads(json.dumps(new.manifest))
            m["binding"]["session"] = f"sess-{now().strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}"
            new = Authority(m)
        return self._install(new, yes=yes, timeout=timeout, action="grant")

    def revoke(self, *, yes: bool = False, timeout: float = 45.0) -> Authority:
        current = self.current()
        if current is None:
            raise AdminError(f"no active authority at {self.manifest}")
        ts = now().strftime("%Y%m%dT%H%M%SZ")
        revoked = Authority({
            "apiVersion": "mcp-remote-sudo/v1", "kind": "TaskAuthority",
            "metadata": {"id": f"revoked-{ts}", "version": 1, "purpose": "Revoked by operator"},
            "binding": dict(current.manifest["binding"]),
            "lifetime": {"notAfter": now().isoformat(), "renewable": False, "expansion": "prohibited"},
            "allow": [], "deny": [],
        })
        return self._install(revoked, yes=yes, timeout=timeout, action="revoke")

    def status(self) -> None:
        a = self.current()
        if a is None:
            self.say(f"no authority at {self.manifest}")
        else:
            remaining = _expires_in(a)
            self.say(f"authority: {a.manifest['metadata']['id']} hash={a.manifest_hash}")
            self.say(f"expires: {a.manifest['lifetime']['notAfter']} ({'EXPIRED' if remaining <= 0 else f'{remaining/3600:.1f}h left'})")
            self.say(f"operations: {sorted(a.allowed_tools)}")
        st = self.read_status()
        if st is None:
            self.say(f"service status file: unavailable ({self.status_path})")
        else:
            loaded = "matches" if a and st.get("manifest_hash") == a.manifest_hash else "DIFFERS from file on disk"
            self.say(f"service loaded: {st.get('manifest_hash')} ({loaded}); last reload ok={st.get('ok')} at {st.get('at')}")
            self.say(f"session: {st.get('session')} ({st.get('session_mode', 'fixed')})")
            if st.get("error"): self.say(f"last reload error: {st['error']}")
        svc = run(["systemctl", "show", self.service, "-p", "ActiveState", "-p", "NRestarts", "--value"])
        if svc.returncode == 0:
            self.say(f"service: {' '.join(svc.stdout.split())}")

    def receipts_verify(self) -> bool:
        if not self.receipts.exists():
            raise AdminError(f"no receipts at {self.receipts}")
        result = verify_chain(self.receipts)
        if result["ok"]:
            self.say(f"receipt chain intact: {result['count']} receipts, head={result['head']}")
        else:
            self.say(f"receipt chain BROKEN at line {result['line']}: {result['reason']} (after {result['count']} valid receipts)")
        return result["ok"]

    def pack_list(self) -> None:
        """Built-in packs, external distributions (metadata only — never imported here), and what the service loaded."""
        a = self.current(); allowed = a.allowed_tools if a else set()
        for pack in self.registry.packs.values():
            self.say(f"{pack.name} {pack.version} (built-in) — {pack.description}")
            for op in pack.operations:
                mark = "exposed" if op.name in allowed else "available"
                self.say(f"  {op.name:<22} {op.tool:<22} {mark}{'  (mutating)' if op.mutating else ''}")
        loaded = (self.read_status() or {}).get("packs", {})
        for dist in pack_install.installed(self.packs_dir):
            self.say(f"{dist['distribution']} {dist['version']} (external, entry points: {dist['entry_points'] or 'none'})")
            for name, info in loaded.items():
                if info.get("distribution") and pack_install.canonical(info["distribution"]) == dist["distribution"]:
                    for op in info.get("operations", []):
                        self.say(f"  {op:<22} {'exposed' if op in allowed else 'available'}")

    def pack_install(self, lockfile: str, *, yes: bool = False, timeout: float = 45.0) -> list[str]:
        """Stage, check and swap in; keep the previous versions until the restarted service shows the new packs."""
        if not yes and input(f"install packs pinned in {lockfile} into {self.packs_dir} and restart {self.service}? [y/N] ").strip().lower() not in ("y", "yes"):
            raise AdminError("aborted by operator")
        try:
            with self._admin_lock(), pack_install.locked(self.packs_dir) as recovered:
                self._report_recovery(recovered, timeout)
                return self._pack_install_locked(lockfile, timeout)
        except pack_install.PackInstallError as exc:
            raise AdminError(str(exc)) from exc

    def _report_recovery(self, recovered: list[str], timeout: float) -> None:
        if recovered:
            self.say(f"recovered from an interrupted pack operation: restored previous {recovered}; restarting")
            self._restart_and_confirm(timeout)

    def _pack_install_locked(self, lockfile: str, timeout: float) -> list[str]:
        try:
            txn = pack_install.install(Path(lockfile), self.packs_dir, run)
        except (pack_install.PackInstallError, OSError) as exc:
            raise AdminError(str(exc)) from exc
        self.say(f"staged and installed: {', '.join(txn.installed)}")
        names = {spec.split("==", 1)[0] for spec in txn.installed}
        expected = {d["distribution"] for d in pack_install.installed(self.packs_dir) if d["entry_points"] and d["distribution"] in names}
        try:
            st = self._restart_and_confirm(timeout)
            loaded = {pack_install.canonical(i.get("distribution") or "") for i in (st.get("packs") or {}).values()}
            missing = sorted(expected - loaded)
            if missing:
                raise AdminError(f"the service restarted but did not load {missing} (is --packs-dir set on the unit?)")
        except BaseException as exc:   # incl. Ctrl-C: never leave unconfirmed packs live
            txn.rollback()
            if not isinstance(exc, AdminError):
                try:
                    self._restart_and_confirm(timeout)   # bring the service back on the restored packs
                except BaseException:
                    pass
                raise exc
            try:
                self._restart_and_confirm(timeout)
                restored = "previous packs restored and service restarted"
            except AdminError as again:
                restored = f"previous packs restored, but the restart did not confirm: {again}"
            raise AdminError(f"pack install failed ({exc}); {restored}") from exc
        txn.commit()
        self.pack_list()
        return txn.installed

    def pack_remove(self, dist: str, *, yes: bool = False, timeout: float = 45.0) -> None:
        try:
            with self._admin_lock(), pack_install.locked(self.packs_dir) as recovered:
                self._report_recovery(recovered, timeout)
                status = self.read_status()
                if status is None or "packs" not in status:
                    raise AdminError("cannot confirm which operations the pack provides (service status unavailable); refusing")
                a = self.current(); allowed = a.allowed_tools if a else set()
                provided = {op for info in status["packs"].values()
                            if info.get("distribution") and pack_install.canonical(info["distribution"]) == pack_install.canonical(dist)
                            for op in info.get("operations", [])}
                referenced = sorted(provided & allowed)
                if referenced:
                    raise AdminError(f"the active authority still allows {referenced} from {dist}; revoke or re-grant first")
                return self._pack_remove_locked(dist, allowed, yes=yes, timeout=timeout)
        except pack_install.PackInstallError as exc:
            raise AdminError(str(exc)) from exc

    def _pack_remove_locked(self, dist: str, allowed: set, *, yes: bool, timeout: float) -> None:
        needed_by = pack_install.dependents(self.packs_dir, dist)
        if needed_by:
            raise AdminError(f"{dist} is required by installed packs {needed_by}; remove those first")
        if not yes and input(f"remove {dist} from {self.packs_dir} and restart {self.service}? [y/N] ").strip().lower() not in ("y", "yes"):
            raise AdminError("aborted by operator")
        if not pack_install.remove(self.packs_dir, dist):
            raise AdminError(f"{dist} is not installed in {self.packs_dir}")
        self.say(f"removed: {pack_install.canonical(dist)}")
        self._restart_and_confirm(timeout)

    def _restart_and_confirm(self, timeout: float) -> dict:
        # A restart (not a reload) gives the service a clean import state after packs change on disk.
        before = (self.read_status() or {}).get("at")
        r = run(["systemctl", "restart", self.service])
        if r.returncode != 0:
            raise AdminError(f"could not restart {self.service}: {r.stderr.strip() or r.returncode}")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            st = self.read_status()
            if st and st.get("at") != before:
                if st.get("ok"):
                    self.say(f"{self.service} restarted; authority {st.get('manifest_hash')} loaded"); return st
                raise AdminError(f"{self.service} restarted but reports: {st.get('error')}")
            time.sleep(0.2)
        raise AdminError(f"{self.service} did not report healthy within {timeout:g}s (see journalctl -u {self.service})")

    # -- install + reload ---------------------------------------------------------------------
    @contextmanager
    def _admin_lock(self):
        """One authority-changing admin operation at a time (grant, revoke, pack install/remove). Always taken
        before the packs lock, so the two locks are acquired in a fixed order."""
        lock_path = self.manifest.with_name(f".{self.manifest.name}.admin.lock")
        with open(lock_path, "a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise AdminError("another mcp-remote-sudo-admin operation is in progress") from None
            yield

    def _install(self, new: Authority, *, yes: bool, timeout: float, action: str) -> Authority:
        # A concurrent grant's rollback must never undo another operator's revoke.
        with self._admin_lock():
            return self._install_locked(new, yes=yes, timeout=timeout, action=action)

    def _install_locked(self, new: Authority, *, yes: bool, timeout: float, action: str) -> Authority:
        current = self.current()
        if current is not None:
            keys = ("agent", "host") if self._session_mode() == "manifest" else ("agent", "session", "host")
            want = {k: current.manifest["binding"][k] for k in keys}; got = {k: new.manifest["binding"][k] for k in keys}
            if got != want:
                raise AdminError(f"binding {got} does not match the active manifest's binding {want}")
        self.out.write(diff_text(current, new))
        if not yes and input(f"{action} this authority? [y/N] ").strip().lower() not in ("y", "yes"):
            raise AdminError("aborted by operator")
        st = self.read_status()
        disk_is_running = current is not None and bool(st) and st.get("manifest_hash") == current.manifest_hash
        if current is not None and st and not disk_is_running:
            self.say(f"warning: {self.manifest} ({current.manifest_hash}) is not what the service runs "
                     f"({st.get('manifest_hash')}); the backup will hold the file on disk, not the running authority")
        backup = self._backup() if current is not None else None
        self._atomic_write(new.manifest)
        written = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        outcome, detail = self._reload_and_confirm(new.manifest_hash, timeout, written)
        if outcome == "loaded":
            self.say(f"{action}: active authority is now {new.manifest['metadata']['id']} ({new.manifest_hash})"
                     + (f"; previous saved to {backup}" if backup else ""))
            return new
        if outcome == "rejected" and action == "grant" and backup is not None \
                and hashlib.sha256(self.manifest.read_bytes()).hexdigest() == written:
            # Only an explicit rejection by the service rolls a grant back; the service kept its previous authority.
            os.replace(backup, self.manifest)
            if not disk_is_running:
                # Re-signalling would activate a file that was never reviewed or loaded: leave the service as it is.
                raise AdminError(f"service rejected the new authority ({detail}); restored {self.manifest} from backup, "
                                 f"but that file differs from what the service runs, so it was NOT reloaded")
            try:
                self._signal_reload()
            except AdminError:
                pass  # the restored file is what the service already runs and what it will load at next start
            raise AdminError(f"service rejected the new authority ({detail}); restored {self.manifest} from backup")
        if outcome == "rejected":
            running = (self.read_status() or {}).get("manifest_hash")
            hint = " To stop all access now, stop the service: systemctl stop " + self.service if action == "revoke" else ""
            raise AdminError(f"{action}: the service REJECTED {new.manifest['metadata']['id']} ({detail}) and still runs "
                             f"{running}; {self.manifest} was left installed and will fail again at the next reload or "
                             f"start until fixed.{hint}")
        # Unconfirmed (busy service, timeout, or signal failure): never roll back. In particular a revoke must stay
        # installed — restoring the previous authority would undo the operator's revocation.
        raise AdminError(f"{action}: {self.manifest} now holds {new.manifest['metadata']['id']} ({new.manifest_hash}), "
                         f"but the service has not confirmed loading it ({detail}). It will apply when the service "
                         f"processes the reload or next starts; check `status`."
                         + (f" Previous saved to {backup}." if backup else ""))

    def _backup(self) -> Path:
        ts = now().strftime("%Y%m%dT%H%M%SZ")
        backup = self.manifest.with_name(f"{self.manifest.name}.bak-{ts}")
        n = 0
        while backup.exists():
            n += 1; backup = self.manifest.with_name(f"{self.manifest.name}.bak-{ts}.{n}")
        backup.write_bytes(self.manifest.read_bytes()); backup.chmod(0o644)
        return backup

    def _atomic_write(self, manifest: dict[str, Any]) -> None:
        tmp = self.manifest.with_name(f".{self.manifest.name}.tmp-{os.getpid()}")
        with tmp.open("w", encoding="utf-8") as fh:
            yaml.safe_dump(manifest, fh, sort_keys=False); fh.flush(); os.fsync(fh.fileno())
        tmp.chmod(0o644)
        os.replace(tmp, self.manifest)

    def _signal_reload(self) -> None:
        r = run(["systemctl", "kill", "--kill-whom=main", "--signal=HUP", self.service])
        if r.returncode != 0:
            raise AdminError(f"could not signal {self.service}: {r.stderr.strip() or r.returncode}")

    def _reload_and_confirm(self, expected_hash: str, timeout: float, file_sha256: str | None = None) -> tuple[str, str]:
        """("loaded" | "rejected" | "pending", detail). Only a status newer than the signal counts."""
        before = (self.read_status() or {}).get("at")
        try:
            self._signal_reload()
        except AdminError as exc:
            return "pending", str(exc)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            st = self.read_status()
            if st and st.get("at") != before:
                if st.get("ok") and st.get("manifest_hash") == expected_hash:
                    return "loaded", "loaded"
                if not st.get("ok") and (st.get("attempted_hash") == expected_hash
                                         or (file_sha256 and st.get("attempted_file_sha256") == file_sha256)):
                    # A verdict about exactly the bytes we wrote — not some other, earlier manifest.
                    return "rejected", st.get("error") or "reload rejected"
                before = st.get("at")   # a different successful reload (e.g. a queued earlier signal): keep waiting
            time.sleep(0.2)
        return "pending", f"no reload confirmation from {self.status_path} within {timeout:g}s (service busy?)"

def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mcp-remote-sudo-admin", description=__doc__.splitlines()[0])
    p.add_argument("--manifest", default=DEFAULT_MANIFEST)
    p.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    p.add_argument("--receipts", default=DEFAULT_RECEIPTS)
    p.add_argument("--service", default=DEFAULT_SERVICE)
    p.add_argument("--session-mode", choices=("manifest", "fixed"), default=None,
                   help="override the service's session mode when its status file is unavailable")
    p.add_argument("--packs-dir", default=DEFAULT_PACKS_DIR)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="validate a manifest file").add_argument("file")
    sub.add_parser("diff", help="diff a manifest file against the active authority").add_argument("file")
    g = sub.add_parser("grant", help="install a manifest as the active authority and reload")
    g.add_argument("file"); g.add_argument("--yes", action="store_true"); g.add_argument("--timeout", type=float, default=45.0)
    r = sub.add_parser("revoke", help="replace the active authority with an expired deny-all authority")
    r.add_argument("--yes", action="store_true"); r.add_argument("--timeout", type=float, default=45.0)
    sub.add_parser("status", help="show the active authority and what the service has loaded")
    rc = sub.add_parser("receipts", help="receipt operations"); rc_sub = rc.add_subparsers(dest="receipts_command", required=True)
    rc_sub.add_parser("verify", help="verify the receipt hash chain")
    pk = sub.add_parser("pack", help="Task Pack operations"); pk_sub = pk.add_subparsers(dest="pack_command", required=True)
    pk_sub.add_parser("list", help="installed packs and which operations the active authority exposes")
    pi = pk_sub.add_parser("install", help="install wheel-only, hash-pinned packs from a lockfile, then restart")
    pi.add_argument("--requirements", required=True); pi.add_argument("--yes", action="store_true"); pi.add_argument("--timeout", type=float, default=45.0)
    pr = pk_sub.add_parser("remove", help="remove an external pack distribution (refused while referenced), then restart")
    pr.add_argument("distribution"); pr.add_argument("--yes", action="store_true"); pr.add_argument("--timeout", type=float, default=45.0)
    a = p.parse_args(argv)
    admin = Admin(a.manifest, a.state_dir, a.receipts, a.service, packs_dir=a.packs_dir)
    admin.session_mode_override = a.session_mode
    try:
        if a.command == "validate": admin.validate(a.file)
        elif a.command == "diff": admin.diff(a.file)
        elif a.command == "grant": admin.grant(a.file, yes=a.yes, timeout=a.timeout)
        elif a.command == "revoke": admin.revoke(yes=a.yes, timeout=a.timeout)
        elif a.command == "status": admin.status()
        elif a.command == "receipts": return 0 if admin.receipts_verify() else 1
        elif a.command == "pack" and a.pack_command == "list": admin.pack_list()
        elif a.command == "pack" and a.pack_command == "install": admin.pack_install(a.requirements, yes=a.yes, timeout=a.timeout)
        elif a.command == "pack" and a.pack_command == "remove": admin.pack_remove(a.distribution, yes=a.yes, timeout=a.timeout)
    except AdminError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
