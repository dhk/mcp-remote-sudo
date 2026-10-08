import json
from types import SimpleNamespace

import pytest
import yaml

from mcp_remote_sudo import approvals, helper as helper_mod, packs, proposals
from mcp_remote_sudo.authority import Authority
from mcp_remote_sudo.helper import Helper

RID = "req-20261003T120000Z-0123abcd"


@pytest.fixture
def ran(monkeypatch):
    calls = []
    def fake_run(argv, capture_output, text, timeout, check):
        calls.append(list(argv)); return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(helper_mod.subprocess, "run", fake_run)
    return calls


def grant(tmp_path, rules):
    m = tmp_path / "authority.yaml"
    m.write_text(yaml.safe_dump({"apiVersion": "mcp-remote-sudo/v1", "kind": "TaskAuthority", "metadata": {"id": "r"},
        "binding": {"agent": "a", "session": "s", "host": "h"},
        "lifetime": {"notAfter": "2099-01-01T00:00:00Z", "renewable": False, "expansion": "prohibited"}, "allow": rules}))
    return m


def handle(h, op, args, rid=RID):
    return h.handle(json.dumps({"request_id": rid, "operation": op, "arguments": args}).encode(), 7)


def test_recovery_ladder_argv_and_inverse(tmp_path, ran):
    m = grant(tmp_path, [{"tool": "wifi.radio.set", "args": {"state": {"enum": ["on", "off"]}}, "confirmation": "grant-only"},
                         {"tool": "service.restart", "args": {"unit": {"enum": ["wpa_supplicant.service"]}}, "confirmation": "grant-only"},
                         {"tool": "kernel.module.reload", "args": {"name": {"enum": ["wl"]}}, "confirmation": "grant-only"}])
    h = Helper(manifest=m, receipts=tmp_path / "hr.jsonl", allowed_uid=7, approvals_dir=tmp_path / "ap")
    radio = handle(h, "wifi.radio.set", {"state": "off"})
    assert radio["ok"] and radio["result"]["inverse"] == {"operation": "wifi.radio.set", "arguments": {"state": "on"}}
    assert handle(h, "service.restart", {"unit": "wpa_supplicant.service"})["ok"]
    assert handle(h, "kernel.module.reload", {"name": "wl"})["ok"]
    assert ran == [["nmcli", "radio", "wifi", "off"], ["systemctl", "restart", "--", "wpa_supplicant.service"],
                   ["modprobe", "-r", "wl"], ["modprobe", "wl"]]


@pytest.mark.parametrize("op,args,rule_args", [
    ("service.restart", {"unit": "ssh.service"}, {}),                                   # open-ended grant
    ("service.restart", {"unit": "ssh.service"}, {"unit": {"minimum": 0}}),             # not an enum
    ("kernel.module.reload", {"name": "b43"}, {}),
    ("wifi.radio.set", {"state": "off"}, {}),
])
def test_helper_refuses_grants_that_do_not_enumerate_resources(tmp_path, ran, op, args, rule_args):
    rule = {"tool": op, "confirmation": "grant-only", **({"args": rule_args} if rule_args else {})}
    h = Helper(manifest=grant(tmp_path, [rule]), receipts=tmp_path / "hr.jsonl", allowed_uid=7, approvals_dir=tmp_path / "ap")
    out = handle(h, op, args)
    assert out["ok"] is False and (out["error"].startswith("grant_must_enumerate") or out["error"].startswith("manifest:"))
    assert ran == []


@pytest.mark.parametrize("op,args", [("service.restart", {"unit": "ssh.socket"}), ("service.restart", {"unit": "-x.service"}),
                                     ("kernel.module.reload", {"name": "wl; reboot"}), ("wifi.radio.set", {"state": "maybe"})])
def test_adapters_validate_even_if_a_grant_allows_bad_values(tmp_path, ran, op, args):
    key = next(iter(args))
    h = Helper(manifest=grant(tmp_path, [{"tool": op, "args": {key: {"enum": [args[key]]}}, "confirmation": "grant-only"}]),
               receipts=tmp_path / "hr.jsonl", allowed_uid=7, approvals_dir=tmp_path / "ap")
    assert handle(h, op, args) == {"ok": False, "error": "failed:ValueError"} and ran == []


def test_module_reload_requires_operator_approval_by_default(tmp_path, ran):
    m = grant(tmp_path, [{"tool": "kernel.module.reload", "args": {"name": {"enum": ["wl"]}}}])
    h = Helper(manifest=m, receipts=tmp_path / "hr.jsonl", allowed_uid=7, approvals_dir=tmp_path / "ap")
    assert handle(h, "kernel.module.reload", {"name": "wl"})["error"] == "operator_approval_missing" and ran == []
    approvals.approve(tmp_path / "ap", RID, "kernel.module.reload", {"name": "wl"}, Authority.load(m).manifest_hash)
    assert handle(h, "kernel.module.reload", {"name": "wl"})["ok"] and ran == [["modprobe", "-r", "wl"], ["modprobe", "wl"]]


def test_remediate_template_proposal():
    reg = packs.default_registry()
    active = Authority({"apiVersion": "mcp-remote-sudo/v1", "kind": "TaskAuthority", "metadata": {"id": "a"},
                        "binding": {"agent": "a", "session": "s", "host": "h"},
                        "lifetime": {"notAfter": "2099-01-01T00:00:00Z", "renewable": False, "expansion": "prohibited"},
                        "allow": [{"tool": "authority.propose"}]})
    m, warnings = proposals.render(registry=reg, active=active, purpose="Recover wedged wl", ttl_minutes=60, constraints=None,
                                   operations=["wifi.radio.set", "service.restart", "kernel.module.reload"])
    rules = {r["tool"]: r["args"] for r in m["allow"]}
    assert rules["kernel.module.reload"] == {"name": {"enum": ["wl"]}}
    assert rules["service.restart"]["unit"]["enum"] == ["wpa_supplicant.service", "NetworkManager.service"]
    assert {"wifi.radio.set is a mutating operation", "kernel.module.reload is a mutating operation"} <= set(warnings)
    assert all("confirmation" not in r for r in m["allow"])   # default = operator approval per action


def test_service_side_ops_are_mutating_and_route_to_helper():
    ops = packs.default_registry().operations
    for name in ("wifi.radio.set", "service.restart", "kernel.module.reload"):
        assert ops[name].mutating and "helper" in ops[name].privileges
