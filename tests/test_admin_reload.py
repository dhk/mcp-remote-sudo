import asyncio, io, json
from pathlib import Path

import pytest
import yaml

from mcp_remote_sudo import admin as admin_mod
from mcp_remote_sudo import packs
from mcp_remote_sudo.admin import Admin, AdminError
from mcp_remote_sudo.authority import Authority
from mcp_remote_sudo.receipts import ReceiptWriter, verify_chain
from mcp_remote_sudo.server import AuthorityReloader, Runtime, build_server

BINDING={"agent":"mcp-remote-sudo","session":"baseline","host":"lobster"}


def manifest(allow, *, id="m", not_after="2099-01-01T00:00:00Z", binding=BINDING):
    return {"apiVersion":"mcp-remote-sudo/v1","kind":"TaskAuthority","metadata":{"id":id,"version":1},
            "binding":dict(binding),"lifetime":{"notAfter":not_after,"renewable":False,"expansion":"prohibited"},
            "allow":[{"tool":t} for t in allow],"deny":[]}


class Host:
    """A fake host: manifest on disk, a running server (runtime + reloader), and systemctl that delivers SIGHUP."""
    def __init__(self, tmp_path, monkeypatch, allow=("system.info","network.status")):
        self.manifest=tmp_path/"authority.yaml"; self.state=tmp_path/"state"; self.state.mkdir()
        self.receipts=tmp_path/"receipts.jsonl"
        self.manifest.write_text(yaml.safe_dump(manifest(allow)))
        self.runtime=Runtime(Authority.load(self.manifest),ReceiptWriter(self.receipts),**BINDING)
        registry=packs.default_registry()
        self.server=build_server(self.runtime,registry=registry)
        self.reloader=AuthorityReloader(self.server,self.runtime,registry,self.manifest,self.state/"authority-status.json")
        self.reloader.write_status(True)
        self.signals=[]
        def fake_run(argv):
            argv=list(argv); self.signals.append(argv)
            if argv[:2]==["systemctl","kill"]: self.reloader.reload()
            class R: returncode=0; stdout="active 0\n"; stderr=""
            return R()
        monkeypatch.setattr(admin_mod,"run",fake_run)
        self.out=io.StringIO()
        self.admin=Admin(str(self.manifest),str(self.state),str(self.receipts),"mcp-remote-sudo.service",out=self.out)

    def tools(self): return {t.name for t in asyncio.run(self.server.list_tools())}

    def write_candidate(self, tmp_path, m, name="new.yaml"):
        p=tmp_path/name; p.write_text(yaml.safe_dump(m)); return p


def test_reload_swaps_authority_and_tools(tmp_path, monkeypatch):
    h=Host(tmp_path,monkeypatch)
    assert h.tools()=={"system_info","network_status"}
    h.manifest.write_text(yaml.safe_dump(manifest(["system.info","wifi.scan"],id="m2")))
    status=h.reloader.reload()
    assert status["ok"] and h.tools()=={"system_info","wifi_scan"}
    assert h.runtime.authority.manifest["metadata"]["id"]=="m2"
    assert json.loads((h.state/"authority-status.json").read_text())["manifest_hash"]==h.runtime.authority.manifest_hash
    last=json.loads(h.receipts.read_text().splitlines()[-1])
    assert last["tool"]=="authority.reload" and last["result"]=="success"


@pytest.mark.parametrize("bad", [
    "not: [valid",                                                         # YAML error
    yaml.safe_dump(manifest(["system.info","kernel.module.set"])),        # no pack provides it
    yaml.safe_dump(manifest(["system.info"],binding={**BINDING,"session":"other"})),  # binding mismatch
])
def test_rejected_reload_keeps_previous_authority(tmp_path, monkeypatch, bad):
    h=Host(tmp_path,monkeypatch); before=h.runtime.authority.manifest_hash
    h.manifest.write_text(bad)
    status=h.reloader.reload()
    assert not status["ok"] and status["error"] and status["manifest_hash"]==before
    assert h.runtime.authority.manifest_hash==before and h.tools()=={"system_info","network_status"}
    assert json.loads(h.receipts.read_text().splitlines()[-1])["result"]=="failed"


def test_grant_installs_backs_up_and_confirms(tmp_path, monkeypatch):
    h=Host(tmp_path,monkeypatch); original=h.manifest.read_text()
    cand=h.write_candidate(tmp_path,manifest(["system.info","wifi.status"],id="granted"))
    new=h.admin.grant(str(cand),yes=True,timeout=2)
    assert h.runtime.authority.manifest_hash==new.manifest_hash and "wifi_status" in h.tools()
    backups=list(tmp_path.glob("authority.yaml.bak-*")); assert len(backups)==1 and backups[0].read_text()==original
    assert ["systemctl","kill","--kill-whom=main","--signal=HUP","mcp-remote-sudo.service"] in h.signals
    assert "operations added: ['wifi.status']" in h.out.getvalue() and "operations removed: ['network.status']" in h.out.getvalue()
    assert verify_chain(h.receipts)["ok"]


def test_grant_rolls_back_when_service_rejects(tmp_path, monkeypatch):
    h=Host(tmp_path,monkeypatch); original=h.manifest.read_text(); before=h.runtime.authority.manifest_hash
    # An operation no installed pack provides: the admin can't know (it never imports external packs); the service can.
    cand=h.write_candidate(tmp_path,manifest(["system.info","example.external"],id="bad"))
    with pytest.raises(AdminError, match="rejected the new authority.*restored"):
        h.admin.grant(str(cand),yes=True,timeout=2)
    assert h.manifest.read_text()==original and h.runtime.authority.manifest_hash==before
    assert sum(1 for s in h.signals if s[:2]==["systemctl","kill"])==2   # reload attempt + reload after restore


@pytest.mark.parametrize("m,match", [
    (manifest(["system.info"],not_after="2020-01-01T00:00:00Z"), "already-expired"),
    (manifest(["system.info"],binding={**BINDING,"host":"elsewhere"}), "does not match the active manifest's binding"),
])
def test_grant_refuses_expired_or_misbound(tmp_path, monkeypatch, m, match):
    h=Host(tmp_path,monkeypatch); before=h.manifest.read_text()
    with pytest.raises(AdminError, match=match):
        h.admin.grant(str(h.write_candidate(tmp_path,m)),yes=True,timeout=2)
    assert h.manifest.read_text()==before and not any(s[:2]==["systemctl","kill"] for s in h.signals)


def test_grant_requires_confirmation(tmp_path, monkeypatch):
    h=Host(tmp_path,monkeypatch); monkeypatch.setattr("builtins.input",lambda prompt: "n")
    with pytest.raises(AdminError, match="aborted"):
        h.admin.grant(str(h.write_candidate(tmp_path,manifest(["system.info"],id="x"))),timeout=2)


def test_revoke_installs_expired_deny_all(tmp_path, monkeypatch):
    h=Host(tmp_path,monkeypatch)
    h.admin.revoke(yes=True,timeout=2)
    a=h.runtime.authority
    assert a.manifest["metadata"]["id"].startswith("revoked-") and a.allowed_tools==set() and h.tools()==set()
    assert a.manifest["binding"]==BINDING


def test_validate_flags_non_builtin_operations(tmp_path, monkeypatch):
    h=Host(tmp_path,monkeypatch)
    h.admin.validate(str(h.write_candidate(tmp_path,manifest(["system.info","example.external"]))))
    assert "not built-in (service verifies against installed packs at grant): ['example.external']" in h.out.getvalue()


def test_admin_never_imports_external_packs(tmp_path, monkeypatch):
    monkeypatch.setattr(packs,"discover_packs",lambda: pytest.fail("admin imported external pack code"))
    h=Host.__new__(Host)  # only need an Admin instance
    Admin(str(tmp_path/"a.yaml"),str(tmp_path),str(tmp_path/"r.jsonl"),"svc").pack_list()


def test_status_and_receipts_verify(tmp_path, monkeypatch):
    h=Host(tmp_path,monkeypatch)
    h.admin.grant(str(h.write_candidate(tmp_path,manifest(["system.info"],id="s"))),yes=True,timeout=2)
    h.admin.status(); out=h.out.getvalue()
    assert "authority: s" in out and "(matches)" in out and "service: active 0" in out
    assert h.admin.receipts_verify() is True
    rows=[json.loads(r) for r in h.receipts.read_text().splitlines()]; rows[-1]["result"]="tampered"
    h.receipts.write_text("".join(json.dumps(r,sort_keys=True)+"\n" for r in rows))
    assert h.admin.receipts_verify() is False and "BROKEN" in h.out.getvalue()


def test_main_exit_codes(tmp_path, monkeypatch, capsys):
    h=Host(tmp_path,monkeypatch)
    common=["--manifest",str(h.manifest),"--state-dir",str(h.state),"--receipts",str(h.receipts)]
    assert admin_mod.main([*common,"validate",str(h.manifest)])==0
    assert admin_mod.main([*common,"validate",str(tmp_path/"missing.yaml")])==1
    assert "error:" in capsys.readouterr().err



def make_busy(h, monkeypatch, signal_ok=True):
    """systemctl accepts (or refuses) the signal but the service never processes it within the wait."""
    def fake_run(argv):
        argv=list(argv); h.signals.append(argv)
        class R: returncode=0 if signal_ok else 1; stdout=""; stderr="" if signal_ok else "Unit not loaded."
        return R()
    monkeypatch.setattr(admin_mod,"run",fake_run)


def test_unconfirmed_revoke_is_never_rolled_back(tmp_path, monkeypatch):
    """Regression (review of #62): a busy service used to make revoke restore the previous authority."""
    h=Host(tmp_path,monkeypatch); make_busy(h,monkeypatch)
    with pytest.raises(AdminError, match="has not confirmed loading it"):
        h.admin.revoke(yes=True,timeout=0.5)
    on_disk=yaml.safe_load(h.manifest.read_text())
    assert on_disk["allow"]==[] and on_disk["metadata"]["id"].startswith("revoked-")
    h.reloader.reload()                                          # the service gets to the queued SIGHUP later
    assert h.tools()==set()


def test_unconfirmed_grant_stays_installed_and_applies_later(tmp_path, monkeypatch):
    h=Host(tmp_path,monkeypatch); make_busy(h,monkeypatch)
    cand=h.write_candidate(tmp_path,manifest(["system.info","wifi.status"],id="later"))
    with pytest.raises(AdminError, match="pending|has not confirmed"):
        h.admin.grant(str(cand),yes=True,timeout=0.5)
    assert yaml.safe_load(h.manifest.read_text())["metadata"]["id"]=="later"
    h.reloader.reload(); assert "wifi_status" in h.tools()


def test_signal_failure_reports_that_the_file_is_installed(tmp_path, monkeypatch):
    h=Host(tmp_path,monkeypatch); make_busy(h,monkeypatch,signal_ok=False)
    cand=h.write_candidate(tmp_path,manifest(["system.info"],id="unsignalled"))
    with pytest.raises(AdminError, match="now holds unsignalled.*could not signal"):
        h.admin.grant(str(cand),yes=True,timeout=0.5)
    assert yaml.safe_load(h.manifest.read_text())["metadata"]["id"]=="unsignalled"


def test_an_unrelated_successful_reload_is_not_mistaken_for_confirmation(tmp_path, monkeypatch):
    h=Host(tmp_path,monkeypatch)
    real=admin_mod.run
    calls={"n":0}
    def fake_run(argv):
        argv=list(argv)
        if argv[:2]==["systemctl","kill"]:
            calls["n"]+=1
            h.reloader.write_status(True)        # a stale/queued reload of the old authority lands first...
            h.reloader.reload()                  # ...then the real one
        class R: returncode=0; stdout=""; stderr=""
        return R()
    monkeypatch.setattr(admin_mod,"run",fake_run)
    new=h.admin.grant(str(h.write_candidate(tmp_path,manifest(["system.info"],id="real"))),yes=True,timeout=2)
    assert h.runtime.authority.manifest_hash==new.manifest_hash


def test_a_rejection_of_some_other_manifest_is_not_this_grants_verdict(tmp_path, monkeypatch):
    """Regression (review of #62): a stale ok:false for an earlier manifest must not roll back the new grant."""
    h=Host(tmp_path,monkeypatch)
    def fake_run(argv):
        if list(argv)[:2]==["systemctl","kill"]:
            st=json.loads((h.state/"authority-status.json").read_text())
            st.update({"ok":False,"error":"earlier manifest Y rejected","attempted_hash":"Y","attempted_file_sha256":"Y","at":"later"})
            (h.state/"authority-status.json").write_text(json.dumps(st))
        class R: returncode=0; stdout=""; stderr=""
        return R()
    monkeypatch.setattr(admin_mod,"run",fake_run)
    cand=h.write_candidate(tmp_path,manifest(["system.info"],id="x"))
    with pytest.raises(AdminError, match="has not confirmed"):
        h.admin.grant(str(cand),yes=True,timeout=0.5)
    assert yaml.safe_load(h.manifest.read_text())["metadata"]["id"]=="x"      # not "restored"


def test_rejected_revoke_says_so_and_points_to_stopping_the_service(tmp_path, monkeypatch):
    h=Host(tmp_path,monkeypatch)
    def fake_run(argv):
        if list(argv)[:2]==["systemctl","kill"]:
            h.reloader.reload()
        class R: returncode=0; stdout=""; stderr=""
        return R()
    monkeypatch.setattr(admin_mod,"run",fake_run)
    def reject(names): raise packs.PackError("simulated: the service refuses exactly this manifest")
    monkeypatch.setattr(h.reloader.registry,"require",reject)
    with pytest.raises(AdminError, match="REJECTED.*systemctl stop"):
        h.admin.revoke(yes=True,timeout=2)
    assert h.tools()=={"system_info","network_status"}       # the service kept the old authority, as reported


def test_warns_when_the_file_on_disk_is_not_what_the_service_runs(tmp_path, monkeypatch):
    h=Host(tmp_path,monkeypatch)
    h.manifest.write_text(yaml.safe_dump(manifest(["system.info"],id="disk-only")))   # never loaded
    h.admin.grant(str(h.write_candidate(tmp_path,manifest(["system.info"],id="g"))),yes=True,timeout=2)
    assert "is not what the service runs" in h.out.getvalue()


def test_rejected_grant_does_not_activate_an_unreviewed_disk_file(tmp_path, monkeypatch):
    """Regression (review of #62): restoring + re-signalling used to load a file the service had never run."""
    h=Host(tmp_path,monkeypatch)
    unreviewed=manifest(["system.info","wifi.scan","wifi.status"],id="unreviewed")
    h.manifest.write_text(yaml.safe_dump(unreviewed))                    # on disk, never loaded
    signals=[]
    def fake_run(argv):
        argv=list(argv); signals.append(argv)
        if argv[:2]==["systemctl","kill"]: h.reloader.reload()
        class R: returncode=0; stdout=""; stderr=""
        return R()
    monkeypatch.setattr(admin_mod,"run",fake_run)
    cand=h.write_candidate(tmp_path,manifest(["system.info","example.external"],id="bad"))   # will be rejected
    with pytest.raises(AdminError, match="NOT reloaded"):
        h.admin.grant(str(cand),yes=True,timeout=2)
    assert sum(1 for x in signals if x[:2]==["systemctl","kill"])==1          # no second signal
    assert h.tools()=={"system_info","network_status"}                          # still the original authority


def test_concurrent_admin_operations_are_refused(tmp_path, monkeypatch):
    import fcntl
    h=Host(tmp_path,monkeypatch)
    with open(h.manifest.with_name(f".{h.manifest.name}.admin.lock"),"a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        with pytest.raises(AdminError, match="in progress"):
            h.admin.revoke(yes=True,timeout=1)


def test_rollback_never_overwrites_a_file_someone_else_installed(tmp_path, monkeypatch):
    h=Host(tmp_path,monkeypatch)
    def fake_run(argv):
        if list(argv)[:2]==["systemctl","kill"]:
            h.reloader.reload()                                                  # rejects "bad" (unknown op)
            h.manifest.write_text(yaml.safe_dump(manifest([],id="someone-elses")))   # e.g. installed out of band
        class R: returncode=0; stdout=""; stderr=""
        return R()
    monkeypatch.setattr(admin_mod,"run",fake_run)
    with pytest.raises(AdminError, match="REJECTED"):
        h.admin.grant(str(h.write_candidate(tmp_path,manifest(["system.info","example.external"],id="bad"))),yes=True,timeout=2)
    assert yaml.safe_load(h.manifest.read_text())["metadata"]["id"]=="someone-elses"


def test_main_applies_a_sighup_queued_during_startup(tmp_path, monkeypatch):
    import signal, sys
    from mcp_remote_sudo import server as srv
    assert signal.getsignal(signal.SIGHUP) not in (signal.SIG_DFL, None)       # installed at import (main thread)
    mpath=tmp_path/"a.yaml"; mpath.write_text(yaml.safe_dump(manifest(["system.info"],id="one")))
    def fake_serve(self):
        async def run():
            mpath.write_text(yaml.safe_dump(manifest(["system.info","network.status"],id="two")))
        return run()
    monkeypatch.setattr(srv.FastMCP,"run_streamable_http_async",fake_serve)
    monkeypatch.setattr(srv,"_EARLY_HUP",[signal.SIGHUP])                        # a SIGHUP arrived while starting
    added=[]
    class Loop:
        def add_signal_handler(self,sig,cb): added.append(sig)
    monkeypatch.setattr(srv.asyncio,"get_running_loop",lambda: Loop())
    monkeypatch.setattr(sys,"argv",["mcp-remote-sudo","--manifest",str(mpath),"--agent","mcp-remote-sudo","--session","baseline",
                                    "--host","lobster","--receipts",str(tmp_path/"r.jsonl"),"--state-dir",str(tmp_path),"--port","18999"])
    srv.main()
    st=json.loads((tmp_path/"authority-status.json").read_text())
    assert added==[signal.SIGHUP] and st["manifest_id"]=="one"
    reloads=[json.loads(x) for x in (tmp_path/"r.jsonl").read_text().splitlines() if '"authority.reload"' in x]
    assert len(reloads)==1 and reloads[0]["result"]=="success"     # the queued startup SIGHUP was applied, once


def test_admin_refuses_root_without_isolated_mode(monkeypatch, capsys):
    import sys as _sys
    monkeypatch.setattr(admin_mod.os, "geteuid", lambda: 0)
    class Flags: isolated = 0
    monkeypatch.setattr(admin_mod.sys, "flags", Flags)
    assert admin_mod.main(["status"]) == 2
    assert "isolated" in capsys.readouterr().err
