import json, os, sys, threading

import pytest
import yaml

from mcp_remote_sudo import helper as helper_mod
from mcp_remote_sudo.helper import Helper, HelperOperation
from mcp_remote_sudo.receipts import verify_chain

SERVICE_UID = 4242


def write_manifest(path, allow, not_after="2099-01-01T00:00:00Z"):
    path.write_text(yaml.safe_dump({"apiVersion": "mcp-remote-sudo/v1", "kind": "TaskAuthority", "metadata": {"id": "h"},
        "binding": {"agent": "a", "session": "s", "host": "h"},
        "lifetime": {"notAfter": not_after, "renewable": False, "expansion": "prohibited"}, "allow": allow}))


@pytest.fixture
def helper(tmp_path):
    calls = []
    ops = {"helper.ping": HelperOperation("helper.ping", lambda: {"pong": True}, {}),
           "test.set": HelperOperation("test.set", lambda state: calls.append(state) or {"state": state}, {"state": str}),
           "test.boom": HelperOperation("test.boom", lambda: 1 / 0, {})}
    m = tmp_path / "authority.yaml"
    write_manifest(m, [{"tool": "helper.ping"}, {"tool": "test.set", "args": {"state": {"enum": ["on"]}}, "confirmation": "grant-only"},
                       {"tool": "test.boom", "confirmation": "grant-only"}])
    h = Helper(manifest=m, receipts=tmp_path / "helper.jsonl", allowed_uid=SERVICE_UID, operations=ops)
    return h, calls, tmp_path


def req(op, args=None, rid="r1"):
    return json.dumps({"request_id": rid, "operation": op, "arguments": args or {}}).encode()


def test_allowed_operation_runs_and_is_receipted(helper):
    h, calls, tmp = helper
    assert h.handle(req("test.set", {"state": "on"}), SERVICE_UID) == {"ok": True, "result": {"state": "on"}}
    assert calls == ["on"]
    last = json.loads((tmp / "helper.jsonl").read_text().splitlines()[-1])
    assert last["component"] == "helper" and last["result"] == "success" and last["peer_uid"] == SERVICE_UID
    assert verify_chain(tmp / "helper.jsonl")["ok"]


@pytest.mark.parametrize("raw,uid,reason", [
    (req("helper.ping"), 0, "peer_not_service_user"),
    (req("helper.ping"), 1000, "peer_not_service_user"),
    (b"not json", SERVICE_UID, "invalid_json"),
    (b"[1,2]", SERVICE_UID, "invalid_request"),
    (json.dumps({"request_id": "r", "operation": "helper.ping", "arguments": {}, "argv": ["sh"]}).encode(), SERVICE_UID, "invalid_request"),
    (req("helper.ping", rid="../x"), SERVICE_UID, "invalid_request_id"),
    (req("shell.exec", {"cmd": "id"}), SERVICE_UID, "operation_not_in_helper_table"),
    (req("test.set", {}), SERVICE_UID, "invalid_arguments"),
    (req("test.set", {"state": "on", "extra": 1}), SERVICE_UID, "invalid_arguments"),
    (req("test.set", {"state": 1}), SERVICE_UID, "invalid_arguments"),
    (req("test.set", {"state": "off"}), SERVICE_UID, "manifest:arguments_not_allowed"),
    (b"x" * (helper_mod.MAX_REQUEST + 1), SERVICE_UID, "request_too_large"),
])
def test_refusals_are_receipted_and_never_execute(helper, raw, uid, reason):
    h, calls, tmp = helper
    assert h.handle(raw, uid) == {"ok": False, "error": reason}
    assert calls == []
    last = json.loads((tmp / "helper.jsonl").read_text().splitlines()[-1])
    assert last["decision"] == "deny" and last["reason"] == reason


def test_helper_rechecks_the_manifest_independently(helper):
    h, calls, tmp = helper
    write_manifest(tmp / "authority.yaml", [{"tool": "helper.ping"}])   # operator revoked test.set
    assert h.handle(req("test.set", {"state": "on"}), SERVICE_UID)["error"] == "manifest:tool_not_allowed"
    write_manifest(tmp / "authority.yaml", [{"tool": "test.set", "confirmation": "grant-only"}], not_after="2020-01-01T00:00:00Z")
    assert h.handle(req("test.set", {"state": "on"}), SERVICE_UID)["error"] == "manifest:manifest_expired"
    (tmp / "authority.yaml").write_text("garbage: [")
    assert h.handle(req("helper.ping"), SERVICE_UID)["error"] == "manifest_unavailable"
    assert calls == []


def test_operation_failure_reports_class_only(helper):
    h, calls, tmp = helper
    assert h.handle(req("test.boom"), SERVICE_UID) == {"ok": False, "error": "failed:ZeroDivisionError"}
    assert json.loads((tmp / "helper.jsonl").read_text().splitlines()[-1])["result"] == "failed"


def test_builtin_table_is_minimal():
    assert set(helper_mod.OPERATIONS) == {"helper.ping"}


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="SO_PEERCRED is Linux-only")
def test_socket_roundtrip_with_peer_credentials(tmp_path):
    m = tmp_path / "authority.yaml"; write_manifest(m, [{"tool": "helper.ping"}])
    path = str(tmp_path / "helper.sock")
    h = Helper(manifest=m, receipts=tmp_path / "helper.jsonl", allowed_uid=os.getuid())
    sock = helper_mod.listening_socket(path)
    t = threading.Thread(target=lambda: h.serve_connection(sock.accept()[0])); t.start()
    assert helper_mod.call("helper.ping", {}, "r1", path=path) == {"ok": True, "result": {"pong": True}}
    t.join(5); sock.close()
    other = Helper(manifest=m, receipts=tmp_path / "h2.jsonl", allowed_uid=os.getuid() + 1)
    sock = helper_mod.listening_socket(path)
    t = threading.Thread(target=lambda: other.serve_connection(sock.accept()[0])); t.start()
    assert helper_mod.call("helper.ping", {}, "r2", path=path) == {"ok": False, "error": "peer_not_service_user"}
    t.join(5); sock.close()
