import asyncio, io, json
from datetime import datetime, timedelta, timezone

import pytest
import yaml

from mcp_remote_sudo import admin as admin_mod
from mcp_remote_sudo import approvals, helper as helper_mod, packs
from mcp_remote_sudo.admin import Admin, AdminError
from mcp_remote_sudo.approvals import ApprovalError
from mcp_remote_sudo.authority import Authority, ManifestError
from mcp_remote_sudo.helper import Helper, HelperOperation
from mcp_remote_sudo.packs import Operation, Param, TaskPack
from mcp_remote_sudo.receipts import ReceiptWriter
from mcp_remote_sudo.server import Runtime, build_server, confirm_mutation

BINDING = {"agent": "a", "session": "s", "host": "h"}
RID = "req-20261003T120000Z-0123abcd"


def manifest_dict(rule_extra=None, allow_more=()):
    rule = {"tool": "wifi.radio.set", "args": {"state": {"enum": ["on", "off"]}}, **(rule_extra or {})}
    return {"apiVersion": "mcp-remote-sudo/v1", "kind": "TaskAuthority", "metadata": {"id": "m"}, "binding": dict(BINDING),
            "lifetime": {"notAfter": "2099-01-01T00:00:00Z", "renewable": False, "expansion": "prohibited"},
            "allow": [rule, *[{"tool": t} for t in allow_more]]}


# ---- approvals --------------------------------------------------------------------------------
def test_approval_is_single_use(tmp_path):
    approvals.approve(tmp_path, RID, "wifi.radio.set", {"state": "on"}, "H")
    approvals.consume(tmp_path, RID, "wifi.radio.set", {"state": "on"}, "H")
    with pytest.raises(ApprovalError, match="missing"):
        approvals.consume(tmp_path, RID, "wifi.radio.set", {"state": "on"}, "H")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("op,args,mh", [("wifi.radio.set", {"state": "off"}, "H"), ("other.op", {"state": "on"}, "H"),
                                        ("wifi.radio.set", {"state": "on"}, "DIFFERENT")])
def test_mismatched_use_refuses_and_burns_the_approval(tmp_path, op, args, mh):
    approvals.approve(tmp_path, RID, "wifi.radio.set", {"state": "on"}, "H")
    with pytest.raises(ApprovalError, match="mismatch"):
        approvals.consume(tmp_path, RID, op, args, mh)
    with pytest.raises(ApprovalError, match="missing"):
        approvals.consume(tmp_path, RID, "wifi.radio.set", {"state": "on"}, "H")


def test_expired_and_malformed_approvals(tmp_path):
    now = datetime(2026, 10, 3, tzinfo=timezone.utc)
    approvals.approve(tmp_path, RID, "wifi.radio.set", {"state": "on"}, "H", now=now)
    with pytest.raises(ApprovalError, match="expired"):
        approvals.consume(tmp_path, RID, "wifi.radio.set", {"state": "on"}, "H", now=now + timedelta(minutes=11))
    (tmp_path / f"{RID}.json").write_text("{")
    with pytest.raises(ApprovalError, match="malformed"):
        approvals.consume(tmp_path, RID, "wifi.radio.set", {"state": "on"}, "H")
    with pytest.raises(ApprovalError, match="invalid request id"):
        approvals.consume(tmp_path, "../../etc/passwd", "x", {}, "H")


def test_approval_file_is_root_only(tmp_path):
    path = approvals.approve(tmp_path / "ap", RID, "wifi.radio.set", {"state": "on"}, "H")
    assert oct(path.stat().st_mode & 0o777) == "0o600" and oct((tmp_path / "ap").stat().st_mode & 0o777) == "0o700"


# ---- authority schema -------------------------------------------------------------------------
@pytest.mark.parametrize("extra", [{"confirmation": "never"}, {"confirmation": True}])
def test_confirmation_values_are_validated(extra):
    with pytest.raises(ManifestError, match="confirmation"):
        Authority(manifest_dict(extra))


def test_confirmation_only_on_allow_rules():
    m = manifest_dict(); m["deny"] = [{"tool": "shell.exec", "confirmation": "operator"}]
    with pytest.raises(ManifestError, match="allow rules only"):
        Authority(m)


# ---- helper enforcement -----------------------------------------------------------------------
@pytest.fixture
def helper_env(tmp_path):
    ran = []
    ops = {"wifi.radio.set": HelperOperation("wifi.radio.set", lambda state: ran.append(state) or {"radio": state}, {"state": str})}
    mpath = tmp_path / "authority.yaml"; mpath.write_text(yaml.safe_dump(manifest_dict()))
    h = Helper(manifest=mpath, receipts=tmp_path / "hr.jsonl", allowed_uid=7, operations=ops, approvals_dir=tmp_path / "ap")
    return h, ran, mpath, tmp_path


def req(state="on", rid=RID):
    return json.dumps({"request_id": rid, "operation": "wifi.radio.set", "arguments": {"state": state}}).encode()


def test_helper_requires_operator_approval_by_default(helper_env):
    h, ran, mpath, tmp = helper_env
    assert h.handle(req(), 7) == {"ok": False, "error": "operator_approval_missing"}
    approvals.approve(tmp / "ap", RID, "wifi.radio.set", {"state": "on"}, Authority.load(mpath).manifest_hash)
    assert h.handle(req(), 7) == {"ok": True, "result": {"radio": "on"}}
    assert h.handle(req(), 7) == {"ok": False, "error": "operator_approval_missing"}   # replay refused
    assert ran == ["on"]


def test_helper_refuses_approval_from_a_previous_grant(helper_env):
    h, ran, mpath, tmp = helper_env
    approvals.approve(tmp / "ap", RID, "wifi.radio.set", {"state": "on"}, Authority.load(mpath).manifest_hash)
    m = manifest_dict(); m["metadata"]["id"] = "regranted"; mpath.write_text(yaml.safe_dump(m))
    assert h.handle(req(), 7)["error"] == "operator_approval_mismatch" and ran == []


def test_helper_honours_grant_only_and_elicitation_rules(helper_env):
    h, ran, mpath, tmp = helper_env
    for mode in ("grant-only", "elicitation"):
        mpath.write_text(yaml.safe_dump(manifest_dict({"confirmation": mode})))
        assert h.handle(req(rid=approvals.new_request_id()), 7)["ok"] is True
    assert ran == ["on", "on"]


# ---- service confirmation flow ----------------------------------------------------------------
class FakeCtx:
    def __init__(self, supported=True, action="accept", confirm=True):
        self.supported, self.action, self.confirm_value, self.asked = supported, action, confirm, []
        outer = self
        class Session:
            def check_client_capability(self, cap): return outer.supported
        self.session = Session()
    async def elicit(self, message, schema):
        self.asked.append(message)
        class R: pass
        r = R(); r.action = self.action; r.data = schema(confirm=self.confirm_value); return r


def runtime_for(tmp_path, rule_extra=None):
    rt = Runtime(Authority(manifest_dict(rule_extra)), ReceiptWriter(tmp_path / "r.jsonl"), **BINDING)
    rt.state_dir = tmp_path
    return rt


OP = Operation("wifi.radio.set", "wifi_radio_set", lambda request_id, state: {"radio": state, "rid": request_id},
               (Param("state", str),), mutating=True)


def run(coro): return asyncio.run(coro)


def last_receipt(tmp_path): return json.loads((tmp_path / "r.jsonl").read_text().splitlines()[-1])


def test_grant_only_proceeds(tmp_path):
    step = run(confirm_mutation(runtime_for(tmp_path, {"confirmation": "grant-only"}), OP, {"state": "on"}, None, None))
    assert approvals.REQUEST_ID.fullmatch(step["proceed"])


@pytest.mark.parametrize("ctx,reason", [(None, "confirmation_unavailable"), (FakeCtx(supported=False), "confirmation_unavailable"),
                                        (FakeCtx(action="decline"), "confirmation_declined"),
                                        (FakeCtx(confirm=False), "confirmation_declined")])
def test_elicitation_fails_closed(tmp_path, ctx, reason):
    rt = runtime_for(tmp_path, {"confirmation": "elicitation"})
    with pytest.raises(PermissionError, match=reason):
        run(confirm_mutation(rt, OP, {"state": "on"}, ctx, None))
    assert last_receipt(tmp_path)["reason"] == reason


def test_elicitation_accept_proceeds_and_shows_the_exact_call(tmp_path):
    ctx = FakeCtx()
    step = run(confirm_mutation(runtime_for(tmp_path, {"confirmation": "elicitation"}), OP, {"state": "off"}, ctx, None))
    assert "proceed" in step and 'wifi.radio.set with {"state": "off"} on h' in ctx.asked[0]


def test_operator_mode_parks_then_requires_matching_retry(tmp_path):
    rt = runtime_for(tmp_path)
    step = run(confirm_mutation(rt, OP, {"state": "on"}, None, None))
    out = step["respond"]; rid = out["request_id"]
    assert out["status"] == "awaiting_operator_approval" and out["approve_command"].endswith(rid)
    assert last_receipt(tmp_path)["result"] == "pending"
    with pytest.raises(PermissionError, match="differ"):
        run(confirm_mutation(rt, OP, {"state": "off"}, None, rid))
    assert run(confirm_mutation(rt, OP, {"state": "on"}, None, rid)) == {"proceed": rid}


def test_end_to_end_operator_loop(tmp_path, monkeypatch):
    """Claude calls → parked → operator approves → Claude retries → helper consumes → replay refused."""
    mpath = tmp_path / "authority.yaml"; mpath.write_text(yaml.safe_dump(manifest_dict()))
    ran = []
    h = Helper(manifest=mpath, receipts=tmp_path / "hr.jsonl", allowed_uid=7, approvals_dir=tmp_path / "ap",
               operations={"wifi.radio.set": HelperOperation("wifi.radio.set", lambda state: ran.append(state) or {"radio": state}, {"state": str})})
    monkeypatch.setattr(helper_mod, "call", lambda op, args, rid, **kw: h.handle(
        json.dumps({"request_id": rid, "operation": op, "arguments": args}).encode(), 7))
    pack = TaskPack("wifi-remediate-test", "1", (Operation("wifi.radio.set", "wifi_radio_set", packs.helper_adapter("wifi.radio.set"),
                                                           (Param("state", str),), mutating=True),))
    rt = Runtime(Authority.load(mpath), ReceiptWriter(tmp_path / "r.jsonl"), **BINDING); rt.state_dir = tmp_path
    server = build_server(rt, registry=packs.Registry([pack]))

    def call(args):
        out = asyncio.run(server.call_tool("wifi_radio_set", args)); content = out[0] if isinstance(out, tuple) else out
        return json.loads(content[0].text)

    parked = call({"state": "on"}); rid = parked["request_id"]
    assert parked["status"] == "awaiting_operator_approval" and ran == []
    adm = Admin(str(mpath), str(tmp_path), str(tmp_path / "r.jsonl"), "svc", out=io.StringIO()); adm.approvals_dir = tmp_path / "ap"
    adm.approve(rid, yes=True)
    assert "operation: wifi.radio.set" in adm.out.getvalue() and 'arguments: {"state": "on"}' in adm.out.getvalue()
    assert call({"state": "on", "request_id": rid}) == {"radio": "on"} and ran == ["on"]
    with pytest.raises(Exception, match="operator_approval_missing"):
        call({"state": "on", "request_id": rid})
    assert ran == ["on"]


def test_admin_approve_refuses_stale_or_disallowed_requests(tmp_path):
    mpath = tmp_path / "authority.yaml"; mpath.write_text(yaml.safe_dump(manifest_dict()))
    adm = Admin(str(mpath), str(tmp_path), str(tmp_path / "r.jsonl"), "svc", out=io.StringIO()); adm.approvals_dir = tmp_path / "ap"
    approvals.write_pending(tmp_path, RID, "wifi.radio.set", {"state": "on"}, "OLD-HASH")
    with pytest.raises(AdminError, match="different authority"):
        adm.approve(RID, yes=True)
    approvals.write_pending(tmp_path, RID, "wifi.radio.set", {"state": "rainbow"}, Authority.load(mpath).manifest_hash)
    with pytest.raises(AdminError, match="does not allow"):
        adm.approve(RID, yes=True)
    with pytest.raises(AdminError, match="no pending request"):
        adm.approve("req-20261003T120000Z-ffffffff", yes=True)
