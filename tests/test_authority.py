from datetime import datetime, timezone
import pytest
from mcp_remote_sudo.authority import Authority, ManifestError
def manifest():
    return {"apiVersion":"mcp-remote-sudo/v1","kind":"TaskAuthority","metadata":{"id":"test","version":1},"binding":{"agent":"a","session":"s","host":"h"},"lifetime":{"notAfter":"2099-01-01T00:00:00Z","renewable":False,"expansion":"prohibited"},"allow":[{"tool":"network.status"},{"tool":"journal.query","args":{"unit":{"enum":["NetworkManager.service"]},"lines":{"maximum":500}}}],"deny":[{"tool":"shell.exec"}],"receipts":{"required":True}}
def test_unlisted_tool_denied(): assert Authority(manifest()).evaluate("system.reboot",{}).reason=="tool_not_allowed"
def test_explicit_deny_wins(): assert Authority(manifest()).evaluate("shell.exec",{}).reason=="explicit_deny"
def test_argument_constraints():
    a=Authority(manifest()); assert a.evaluate("journal.query",{"unit":"NetworkManager.service","lines":500}).allowed
    assert not a.evaluate("journal.query",{"unit":"ssh.service","lines":100}).allowed
    assert not a.evaluate("journal.query",{"unit":"NetworkManager.service","lines":501}).allowed
def test_expired_manifest_denied():
    m=manifest(); m["lifetime"]["notAfter"]="2020-01-01T00:00:00Z"
    assert Authority(m).evaluate("network.status",{},now=datetime.now(timezone.utc)).reason=="manifest_expired"
def test_binding_mismatch_denied():
    d=Authority(manifest()).check_binding(agent="wrong",session="s",host="h"); assert not d.allowed
def test_unknown_manifest_field_fails_closed():
    m=manifest(); m["surprise"]=True
    with pytest.raises(ManifestError): Authority(m)


def test_unknown_rule_field_fails_closed():
    m=manifest(); m["allow"][1]["arguments"]=m["allow"][1].pop("args")
    with pytest.raises(ManifestError): Authority(m)
