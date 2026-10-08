import io, json

import pytest
import yaml

from mcp_remote_sudo import admin as admin_mod
from mcp_remote_sudo import packs
from mcp_remote_sudo.admin import Admin
from mcp_remote_sudo.authority import Authority
from mcp_remote_sudo.receipts import ReceiptWriter
from mcp_remote_sudo.server import AuthorityReloader, Runtime, build_server


def manifest(session, allow=("system.info",), id="m"):
    return {"apiVersion":"mcp-remote-sudo/v1","kind":"TaskAuthority","metadata":{"id":id},
            "binding":{"agent":"mcp-remote-sudo","session":session,"host":"lobster"},
            "lifetime":{"notAfter":"2099-01-01T00:00:00Z","renewable":False,"expansion":"prohibited"},
            "allow":[{"tool":t} for t in allow]}


@pytest.fixture
def host(tmp_path, monkeypatch):
    """A service started WITHOUT --session: the session comes from the active manifest."""
    m=tmp_path/"authority.yaml"; m.write_text(yaml.safe_dump(manifest("sess-initial")))
    rt=Runtime(Authority.load(m),ReceiptWriter(tmp_path/"r.jsonl"),agent="mcp-remote-sudo",session=None,host="lobster")
    reg=packs.default_registry(); server=build_server(rt,registry=reg)
    rl=AuthorityReloader(server,rt,reg,m,tmp_path/"authority-status.json"); rl.write_status(True)
    def fake_run(argv):
        if list(argv)[:2]==["systemctl","kill"]: rl.reload()
        class R: returncode=0; stdout=""; stderr=""
        return R()
    monkeypatch.setattr(admin_mod,"run",fake_run)
    adm=Admin(str(m),str(tmp_path),str(tmp_path/"r.jsonl"),"svc",out=io.StringIO())
    return tmp_path, rt, rl, adm


def test_session_comes_from_manifest(host):
    tmp, rt, rl, adm = host
    assert rt.session=="sess-initial" and rt.session_mode=="manifest"
    assert json.loads((tmp/"authority-status.json").read_text())["session_mode"]=="manifest"


def test_each_grant_mints_a_new_session_and_receipts_follow_it(host):
    tmp, rt, rl, adm = host
    cand=tmp/"c.yaml"; cand.write_text(yaml.safe_dump(manifest("whatever-the-author-wrote",id="g1")))
    adm.grant(str(cand),yes=True,timeout=2); first=rt.session
    adm.grant(str(cand),yes=True,timeout=2); second=rt.session
    assert first.startswith("sess-") and second.startswith("sess-") and first!=second!="whatever-the-author-wrote"
    rows=[json.loads(x) for x in (tmp/"r.jsonl").read_text().splitlines()]
    assert [r["session"] for r in rows[-2:]]==[first,second]
    assert rows[-1]["previous_session"]==first


def test_manifest_mode_still_checks_agent_and_host(host):
    tmp, rt, rl, adm = host
    bad=manifest("s"); bad["binding"]["host"]="elsewhere"
    cand=tmp/"c.yaml"; cand.write_text(yaml.safe_dump(bad))
    with pytest.raises(admin_mod.AdminError, match="does not match"):
        adm.grant(str(cand),yes=True,timeout=2)
    (tmp/"authority.yaml").write_text(yaml.safe_dump(bad))
    assert rl.reload()["ok"] is False and rt.session=="sess-initial"


def test_fixed_session_mode_is_unchanged(tmp_path):
    m=tmp_path/"a.yaml"; m.write_text(yaml.safe_dump(manifest("baseline")))
    rt=Runtime(Authority.load(m),ReceiptWriter(tmp_path/"r.jsonl"),agent="mcp-remote-sudo",session="baseline",host="lobster")
    assert rt.session_mode=="fixed"
    with pytest.raises(ValueError, match="binding_mismatch:session"):
        Runtime(Authority(manifest("other")),ReceiptWriter(tmp_path/"r2.jsonl"),agent="mcp-remote-sudo",session="baseline",host="lobster")
