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
    with pytest.raises(AdminError, match="restored"):
        h.admin.grant(str(cand),yes=True,timeout=2)
    assert h.manifest.read_text()==original and h.runtime.authority.manifest_hash==before
    assert sum(1 for s in h.signals if s[:2]==["systemctl","kill"])==2   # reload attempt + reload after restore


@pytest.mark.parametrize("m,match", [
    (manifest(["system.info"],not_after="2020-01-01T00:00:00Z"), "already-expired"),
    (manifest(["system.info"],binding={**BINDING,"host":"elsewhere"}), "does not match the service binding"),
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
