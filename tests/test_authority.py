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


def test_wifi_pack_constraints_are_manifest_enforced():
    m=manifest()
    m["allow"].extend([
        {"tool":"wifi.driver.status","args":{"module":{"enum":["wl"]}}},
        {"tool":"kernel.wifi.log","args":{"lines":{"minimum":1,"maximum":200}}},
        {"tool":"network.probe","args":{"target":{"enum":["192.168.7.1","1.1.1.1"]},"count":{"minimum":1,"maximum":4}}},
    ])
    a=Authority(m)
    assert a.evaluate("wifi.driver.status",{"module":"wl"}).allowed
    assert not a.evaluate("wifi.driver.status",{"module":"b43"}).allowed
    assert a.evaluate("kernel.wifi.log",{"lines":100}).allowed
    assert not a.evaluate("kernel.wifi.log",{"lines":500}).allowed
    assert a.evaluate("network.probe",{"target":"1.1.1.1","count":4}).allowed
    assert not a.evaluate("network.probe",{"target":"8.8.8.8","count":4}).allowed


@pytest.mark.parametrize("section,key,value", [
    ("metadata","owner","x"), ("binding","user","x"), ("lifetime","ttl","30m"),
    ("lifetime","notAftr","2099-01-01T00:00:00Z"), ("receipts","path","/tmp/r"),
])
def test_unknown_nested_field_fails_closed(section, key, value):
    m=manifest(); m[section][key]=value
    with pytest.raises(ManifestError, match=f"{section} has unknown fields"): Authority(m)


@pytest.mark.parametrize("section,key,value", [
    ("metadata","version","1"), ("metadata","version",True), ("binding","host",7),
    ("lifetime","renewable","false"), ("receipts","required","yes"),
])
def test_nested_field_type_checked(section, key, value):
    m=manifest(); m[section][key]=value
    with pytest.raises(ManifestError, match="invalid type"): Authority(m)


@pytest.mark.parametrize("section,key", [("metadata","id"),("binding","session"),("receipts","required")])
def test_missing_nested_required_field(section, key):
    m=manifest(); del m[section][key]
    with pytest.raises(ManifestError, match=f"missing required field: {section}.{key}"): Authority(m)


@pytest.mark.parametrize("spec", [
    {"maximun":500}, {}, {"enum":"NetworkManager.service"}, {"enum":[]}, {"maximum":"500"},
    {"minimum":True}, {"minimum":5,"maximum":1}, ["a","b"], None,
])
def test_invalid_constraint_fails_at_load(spec):
    m=manifest(); m["allow"][1]["args"]["lines"]=spec
    with pytest.raises(ManifestError): Authority(m)


def test_valid_optional_fields_and_exact_value_constraint_load():
    m=manifest(); m["metadata"]["purpose"]="diagnose"
    m["allow"].append({"tool":"wifi.driver.status","args":{"module":"wl"}})
    a=Authority(m)
    assert a.evaluate("wifi.driver.status",{"module":"wl"}).allowed
    assert not a.evaluate("wifi.driver.status",{"module":"b43"}).allowed


def test_installer_baseline_manifest_still_loads():
    m=manifest(); del m["receipts"]; m["deny"]=[]
    m["allow"]=[{"tool":"journal.query","args":{"lines":{"minimum":1,"maximum":500}}}]
    Authority(m)


def test_readme_example_manifest_is_valid():
    import re, yaml
    from pathlib import Path
    readme=(Path(__file__).resolve().parents[1]/"README.md").read_text()
    block=next(b for b in re.findall(r"```yaml\n(.*?)```", readme, re.S) if "kind: TaskAuthority" in b)
    Authority(yaml.safe_load(block))


def test_booleans_never_match_numbers():
    m=manifest(); m["allow"].append({"tool":"x.flag","args":{"count":True}})
    m["allow"].append({"tool":"x.enum","args":{"count":{"enum":[1,2]}}})
    m["allow"].append({"tool":"x.range","args":{"count":{"minimum":0,"maximum":5}}})
    a=Authority(m)
    assert a.evaluate("x.flag",{"count":True}).allowed
    assert not a.evaluate("x.flag",{"count":1}).allowed
    assert not a.evaluate("x.enum",{"count":True}).allowed
    assert a.evaluate("x.enum",{"count":1}).allowed
    assert not a.evaluate("x.range",{"count":True}).allowed


@pytest.mark.parametrize("bound", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_bounds_fail_at_load(bound):
    m=manifest(); m["allow"][1]["args"]["lines"]={"maximum":bound}
    with pytest.raises(ManifestError, match="finite"): Authority(m)


def test_non_finite_argument_values_denied():
    a=Authority(manifest())
    assert not a.evaluate("journal.query",{"unit":"NetworkManager.service","lines":float("nan")}).allowed


def test_mixed_type_unknown_keys_raise_manifest_error():
    m=manifest(); m["metadata"]["owner"]="x"; m["metadata"][1]="y"
    with pytest.raises(ManifestError, match="unknown fields"): Authority(m)


def test_readme_example_manifest_is_not_expired():
    import re, yaml
    from pathlib import Path
    readme=(Path(__file__).resolve().parents[1]/"README.md").read_text()
    block=next(b for b in re.findall(r"```yaml\n(.*?)```", readme, re.S) if "kind: TaskAuthority" in b)
    a=Authority(yaml.safe_load(block))
    assert a.evaluate("network.status",{}).reason!="manifest_expired"
