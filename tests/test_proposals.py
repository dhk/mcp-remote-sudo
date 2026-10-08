import asyncio, hashlib, io, json
from datetime import datetime, timezone

import pytest
import yaml

from mcp_remote_sudo import admin as admin_mod
from mcp_remote_sudo import packs, proposals
from mcp_remote_sudo.admin import Admin, AdminError
from mcp_remote_sudo.authority import Authority
from mcp_remote_sudo.proposals import ProposalError, read_for_grant, render, store
from mcp_remote_sudo.receipts import ReceiptWriter
from mcp_remote_sudo.server import AuthorityReloader, Runtime, build_server

BINDING = {"agent": "mcp-remote-sudo", "session": "baseline", "host": "lobster"}
NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def active(allow=("system.info", "authority.propose")):
    return Authority({"apiVersion": "mcp-remote-sudo/v1", "kind": "TaskAuthority", "metadata": {"id": "active"},
                      "binding": dict(BINDING),
                      "lifetime": {"notAfter": "2099-01-01T00:00:00Z", "renewable": False, "expansion": "prohibited"},
                      "allow": [{"tool": t} for t in allow]})


REG = packs.default_registry()


def test_render_applies_templates_and_caller_constraints():
    m, warnings = render(registry=REG, active=active(), purpose="Diagnose wl", now=NOW, ttl_minutes=90,
                         operations=["kernel.wifi.log", "network.probe", "wifi.driver.status", "system.info"],
                         constraints={"network.probe": {"target": {"enum": ["192.168.7.1", "1.1.1.1"]}},
                                      "wifi.driver.status": {"module": {"enum": ["wl"]}}})
    rules = {r["tool"]: r.get("args", {}) for r in m["allow"]}
    assert rules["kernel.wifi.log"]["lines"] == {"minimum": 1, "maximum": 200}            # from template
    assert rules["network.probe"] == {"count": {"minimum": 1, "maximum": 4},
                                      "target": {"enum": ["192.168.7.1", "1.1.1.1"]}}      # template + caller
    assert m["binding"] == BINDING and m["lifetime"]["notAfter"] == "2026-10-03T13:30:00+00:00"
    assert m["lifetime"]["renewable"] is False and m["lifetime"]["expansion"] == "prohibited"
    assert "kernel.wifi.log.boot is unconstrained" in warnings
    assert not any(w.startswith("network.probe.target") for w in warnings)
    Authority(m)


@pytest.mark.parametrize("kwargs,match", [
    ({"operations": ["shell.exec"]}, "no installed pack provides"),
    ({"operations": []}, "operations must be"),
    ({"operations": ["system.info"], "constraints": {"wifi.scan": {}}}, "not proposed"),
    ({"operations": ["network.probe"], "constraints": {"network.probe": {"host": {"enum": ["x"]}}}}, "no arguments"),
    ({"operations": ["system.info"], "ttl_minutes": 2}, "ttl_minutes"),
    ({"operations": ["system.info"], "ttl_minutes": 100000}, "ttl_minutes"),
    ({"operations": ["system.info"], "purpose": ""}, "purpose"),
    ({"operations": ["network.probe"], "constraints": {"network.probe": {"count": {"maximun": 4}}}}, "unknown constraint"),
])
def test_render_rejects_bad_requests(kwargs, match):
    args = {"registry": REG, "active": active(), "purpose": "p", "ttl_minutes": 60, "constraints": None, **kwargs}
    with pytest.raises(Exception, match=match):
        render(**args)


def test_store_and_read_for_grant_by_digest(tmp_path):
    m, _ = render(registry=REG, active=active(), purpose="p", operations=["system.info"], constraints=None, ttl_minutes=60)
    pid, path, digest = store(tmp_path, m)
    assert proposals.PROPOSAL_ID.fullmatch(pid) and hashlib.sha256(path.read_bytes()).hexdigest() == digest
    assert read_for_grant(tmp_path, pid, digest) == m
    path.write_text(path.read_text().replace("system.info", "network.status"))   # swapped after review
    with pytest.raises(ProposalError, match="changed since review"):
        read_for_grant(tmp_path, pid, digest)


@pytest.mark.parametrize("pid,digest", [("../../etc/shadow", "a" * 64), ("prop-20261003T120000Z-abcdef", "ABC"),
                                        ("prop-20261003T120000Z-abcdef/../x", "a" * 64)])
def test_read_for_grant_rejects_bad_ids_and_digests(tmp_path, pid, digest):
    with pytest.raises(ProposalError, match="invalid proposal id|--sha256"):
        read_for_grant(tmp_path, pid, digest)


def test_store_prunes_old_proposals(tmp_path, monkeypatch):
    monkeypatch.setattr(proposals, "MAX_PROPOSALS", 3)
    m, _ = render(registry=REG, active=active(), purpose="p", operations=["system.info"], constraints=None, ttl_minutes=60)
    for i in range(5):
        store(tmp_path, m, now=datetime(2026, 10, 3, 12, 0, i, tzinfo=timezone.utc))
    assert len(list(proposals.proposals_dir(tmp_path).glob("prop-*.yaml"))) == 3


def call(server, name, args):
    out = asyncio.run(server.call_tool(name, args))
    content = out[0] if isinstance(out, tuple) else out
    return json.loads(content[0].text)


def test_propose_then_grant_by_digest_end_to_end(tmp_path, monkeypatch):
    mpath = tmp_path / "authority.yaml"; mpath.write_text(yaml.safe_dump(active().manifest))
    rt = Runtime(Authority.load(mpath), ReceiptWriter(tmp_path / "r.jsonl"), **BINDING)
    server = build_server(rt, registry=REG); rt.state_dir = tmp_path
    rl = AuthorityReloader(server, rt, REG, mpath, tmp_path / "authority-status.json"); rl.write_status(True)
    before = rt.authority.manifest_hash

    out = call(server, "authority_propose", {"purpose": "Diagnose wl", "operations": ["wifi.status", "kernel.wifi.log"],
                                             "ttl_minutes": 60})
    assert rt.authority.manifest_hash == before                      # proposing grants nothing
    assert "wifi_status" not in {t.name for t in asyncio.run(server.list_tools())}
    assert out["grant_command"].endswith(f"--proposal {out['id']} --sha256 {out['sha256']}")
    assert "operations added: ['kernel.wifi.log', 'wifi.status']" in out["diff"]

    def fake_run(argv):
        if list(argv)[:2] == ["systemctl", "kill"]: rl.reload()
        class R: returncode = 0; stdout = ""; stderr = ""
        return R()
    monkeypatch.setattr(admin_mod, "run", fake_run)
    adm = Admin(str(mpath), str(tmp_path), str(tmp_path / "r.jsonl"), "svc", out=io.StringIO())
    with pytest.raises(AdminError, match="changed since review"):
        adm.grant_proposal(out["id"], "0" * 64, yes=True, timeout=2)
    adm.grant_proposal(out["id"], out["sha256"], yes=True, timeout=2)
    assert {"wifi_status", "kernel_wifi_log"} <= {t.name for t in asyncio.run(server.list_tools())}
    assert "authority_propose" in {t.name for t in asyncio.run(server.list_tools())}   # kept: the agent can still ask
    assert "review before granting:" in adm.out.getvalue()
    assert "expires_at" in out


def test_admin_grant_cli_requires_file_xor_proposal(capsys):
    assert admin_mod.main(["grant"]) == 1
    assert admin_mod.main(["grant", "x.yaml", "--proposal", "prop-20261003T120000Z-abcdef", "--sha256", "a" * 64]) == 1
    assert admin_mod.main(["grant", "--proposal", "prop-20261003T120000Z-abcdef"]) == 1
    assert "either FILE or --proposal" in capsys.readouterr().err



def test_widening_a_template_bound_is_flagged():
    m, warnings = render(registry=REG, active=active(), purpose="p", ttl_minutes=60, operations=["journal.query", "network.probe"],
                         constraints={"journal.query": {"lines": {"minimum": 1}},
                                      "network.probe": {"count": {"minimum": 1, "maximum": 100000}, "target": {"enum": ["1.1.1.1"]}}})
    assert any("journal.query.lines" in w and "widens the pack template" in w for w in warnings)
    assert any("journal.query.lines has a one-sided bound" in w for w in warnings)
    assert any("network.probe.count" in w and "widens the pack template" in w for w in warnings)


def test_narrowing_a_template_bound_is_not_flagged():
    _, warnings = render(registry=REG, active=active(), purpose="p", ttl_minutes=60, operations=["network.probe"],
                         constraints={"network.probe": {"count": {"minimum": 1, "maximum": 2}, "target": {"enum": ["1.1.1.1"]}}})
    assert not any("widens" in w for w in warnings)


def test_grant_recomputes_warnings_from_the_verified_bytes(tmp_path, monkeypatch):
    m, _ = render(registry=REG, active=active(), purpose="p", ttl_minutes=60, operations=["journal.query"],
                  constraints={"journal.query": {"lines": {"minimum": 1, "maximum": 10000}}})
    pid, path, digest = store(tmp_path, m)
    mpath = tmp_path / "authority.yaml"; mpath.write_text(yaml.safe_dump(active().manifest))
    adm = Admin(str(mpath), str(tmp_path), str(tmp_path / "r.jsonl"), "svc", out=io.StringIO())
    adm.session_mode_override = "fixed"
    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    with pytest.raises(AdminError, match="aborted"):
        adm.grant_proposal(pid, digest)
    assert "! journal.query.lines" in adm.out.getvalue() and "widens the pack template" in adm.out.getvalue()


def test_root_refuses_symlinked_special_or_oversized_proposals(tmp_path):
    import os
    m, _ = render(registry=REG, active=active(), purpose="p", operations=["system.info"], constraints=None, ttl_minutes=60)
    pid, path, digest = store(tmp_path, m)
    secret = tmp_path / "secret"; secret.write_text("root only")
    path.unlink(); path.symlink_to(secret)
    with pytest.raises(ProposalError, match="cannot open"):
        read_for_grant(tmp_path, pid, digest)
    path.unlink(); os.mkfifo(path)
    with pytest.raises(ProposalError, match="not a regular file"):
        read_for_grant(tmp_path, pid, digest)
    path.unlink(); path.write_bytes(b"x" * (proposals.MAX_PROPOSAL_BYTES + 1))
    with pytest.raises(ProposalError, match="too large"):
        read_for_grant(tmp_path, pid, digest)
    real = proposals.proposals_dir(tmp_path); moved = tmp_path / "elsewhere"; real.rename(moved); real.symlink_to(moved)
    with pytest.raises(ProposalError, match="not a plain directory"):
        read_for_grant(tmp_path, pid, digest)


def test_digest_mismatch_does_not_echo_the_actual_digest(tmp_path):
    m, _ = render(registry=REG, active=active(), purpose="p", operations=["system.info"], constraints=None, ttl_minutes=60)
    pid, path, digest = store(tmp_path, m)
    with pytest.raises(ProposalError) as exc:
        read_for_grant(tmp_path, pid, "0" * 64)
    assert digest not in str(exc.value)


@pytest.mark.parametrize("op,arg,value", [("journal.query","lines",500), ("journal.query","lines",0), ("network.probe","count",True)])
def test_exact_values_outside_the_template_are_flagged(op, arg, value):
    extra = {"target": {"enum": ["1.1.1.1"]}} if op == "network.probe" else {}
    _, warnings = render(registry=REG, active=active(), purpose="p", ttl_minutes=60, operations=[op],
                         constraints={op: {arg: value, **extra}})
    assert any(f"{op}.{arg}" in w and "widens the pack template" in w for w in warnings)


def test_a_templated_read_only_proposal_has_no_noise():
    _, warnings = render(registry=REG, active=active(), purpose="p", ttl_minutes=60,
                         operations=["system.info", "kernel.wifi.log", "receipts.tail"], constraints=None)
    assert [w for w in warnings if "authority.propose" in w] == []
    assert not any("receipts.tail" in w for w in warnings)
