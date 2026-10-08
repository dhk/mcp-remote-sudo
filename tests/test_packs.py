import json
import asyncio

import pytest

from mcp_remote_sudo import packs
from mcp_remote_sudo.authority import Authority
from mcp_remote_sudo.packs import Operation, PackError, Param, Registry, TaskPack
from mcp_remote_sudo.server import build_server

BUILTIN = {"system.info","network.status","systemd.status","journal.query","journal.boots","receipts.tail",
           "wifi.status","wifi.scan","wifi.link","wifi.driver.status","kernel.wifi.log","network.probe"}


class RecordingRuntime:
    def __init__(self, allowed):
        self.calls=[]
        self.authority=Authority({
            "apiVersion":"mcp-remote-sudo/v1","kind":"TaskAuthority",
            "metadata":{"id":"packs-test","version":1},
            "binding":{"agent":"a","session":"s","host":"h"},
            "lifetime":{"notAfter":"2099-01-01T00:00:00Z","renewable":False,"expansion":"prohibited"},
            "allow":[{"tool":t} for t in allowed],"deny":[],
        })

    def invoke(self, tool, args, fn):
        self.calls.append((tool,args)); return {"ok":True}


def tools(server):
    return {t.name:t for t in asyncio.run(server.list_tools())}


def test_builtin_packs_provide_the_existing_operations():
    assert set(packs.default_registry().operations) == BUILTIN


def test_tool_schema_comes_from_pack_declaration():
    t=tools(build_server(RecordingRuntime({"network.probe","journal.query"})))
    probe=t["connectivity_probe"].inputSchema
    assert probe["required"]==["target"]
    assert probe["properties"]["count"]["default"]==4 and probe["properties"]["count"]["type"]=="integer"
    assert t["journal_query"].inputSchema["required"]==["unit"]


def test_invocation_receives_normalized_arguments():
    rt=RecordingRuntime({"network.probe","system.info"}); server=build_server(rt)
    asyncio.run(server.call_tool("connectivity_probe",{"target":"1.1.1.1"}))
    asyncio.run(server.call_tool("system_info",{}))
    assert rt.calls==[("network.probe",{"target":"1.1.1.1","count":4}),("system.info",{})]


def test_allowed_operation_without_a_pack_fails_closed():
    with pytest.raises(PackError, match="kernel.module.set"):
        build_server(RecordingRuntime({"network.status","kernel.module.set"}))


def test_external_pack_is_exposed_only_when_allowed(monkeypatch):
    ext=TaskPack("example","1",(Operation("example.ping","example_ping",lambda: {"pong":True}),))
    class EP:
        name="example"
        def load(self): return lambda: ext
    monkeypatch.setattr(packs,"entry_points",lambda group: [EP()] if group==packs.ENTRY_POINT_GROUP else [])
    assert "example_ping" in tools(build_server(RecordingRuntime({"example.ping"})))
    assert "example_ping" not in tools(build_server(RecordingRuntime({"system.info"})))


def test_entry_point_must_provide_a_task_pack(monkeypatch):
    class EP:
        name="bad"
        def load(self): return {"not":"a pack"}
    monkeypatch.setattr(packs,"entry_points",lambda group: [EP()])
    with pytest.raises(PackError, match="did not provide a TaskPack"):
        packs.discover_packs()


def test_duplicate_operation_or_tool_names_rejected():
    a=TaskPack("a","1",(Operation("x.op","x_op",dict),))
    with pytest.raises(PackError, match="more than one pack"):
        Registry([a,TaskPack("b","1",(Operation("x.op","other",dict),))])
    with pytest.raises(PackError, match="MCP tool name"):
        Registry([a,TaskPack("b","1",(Operation("y.op","x_op",dict),))])
    with pytest.raises(PackError, match="duplicate pack"):
        Registry([a,a])


def test_normalize_drops_unknown_and_fills_defaults():
    op=Operation("n.op","n_op",dict,(Param("a",str),Param("b",int,3)))
    assert op.normalize({"a":"x","zzz":1})=={"a":"x","b":3}


def test_readme_example_manifest_resolves_against_installed_packs():
    import re, yaml
    from pathlib import Path
    readme=(Path(__file__).resolve().parents[1]/"README.md").read_text()
    block=next(b for b in re.findall(r"```yaml\n(.*?)```", readme, re.S) if "kind: TaskAuthority" in b)
    packs.default_registry().require(Authority(yaml.safe_load(block)).allowed_tools)


def test_widening_arguments_require_an_explicit_grant_constraint(tmp_path, monkeypatch):
    from mcp_remote_sudo import adapters
    from mcp_remote_sudo.receipts import ReceiptWriter
    from mcp_remote_sudo.server import Runtime
    monkeypatch.setattr(adapters,"run",lambda argv,timeout=15,**kw: {"argv":list(argv),"returncode":0,"stdout":"","stderr":""})
    def server_for(rule_args):
        m={"apiVersion":"mcp-remote-sudo/v1","kind":"TaskAuthority","metadata":{"id":"g"},
           "binding":{"agent":"a","session":"s","host":"h"},
           "lifetime":{"notAfter":"2099-01-01T00:00:00Z","renewable":False,"expansion":"prohibited"},
           "allow":[{"tool":"kernel.wifi.log",**({"args":rule_args} if rule_args else {})}]}
        rt=Runtime(Authority(m),ReceiptWriter(tmp_path/"r.jsonl"),agent="a",session="s",host="h")
        return build_server(rt)
    legacy=server_for({"lines":{"maximum":200}})            # a manifest written before boot/include_firewall existed
    asyncio.run(legacy.call_tool("kernel_wifi_log",{"lines":50}))  # defaults: still allowed
    for widening in ({"boot":-1},{"include_firewall":True}):
        with pytest.raises(Exception, match="unconstrained_argument"):
            asyncio.run(legacy.call_tool("kernel_wifi_log",{"lines":50,**widening}))
    asyncio.run(legacy.call_tool("kernel_wifi_log",{"lines":50,"since_minutes":10}))   # narrows: not gated
    pinned=server_for({"lines":{"maximum":200},"boot":{"minimum":-3,"maximum":0}})
    asyncio.run(pinned.call_tool("kernel_wifi_log",{"lines":50,"boot":-1}))   # explicitly granted
    with pytest.raises(Exception, match="arguments_not_allowed"):
        asyncio.run(pinned.call_tool("kernel_wifi_log",{"lines":50,"boot":-4}))
    rows=[json.loads(x) for x in (tmp_path/"r.jsonl").read_text().splitlines()]
    assert [r["reason"] for r in rows if r["decision"]=="deny"][:2]==["unconstrained_argument:boot","unconstrained_argument:include_firewall"]


def test_gated_argument_can_be_granted_by_a_later_rule():
    a=Authority({"apiVersion":"mcp-remote-sudo/v1","kind":"TaskAuthority","metadata":{"id":"g"},
        "binding":{"agent":"a","session":"s","host":"h"},
        "lifetime":{"notAfter":"2099-01-01T00:00:00Z","renewable":False,"expansion":"prohibited"},
        "allow":[{"tool":"kernel.wifi.log","args":{"lines":{"maximum":200}}},
                 {"tool":"kernel.wifi.log","args":{"lines":{"maximum":200},"boot":{"minimum":-3,"maximum":0}}}]})
    args={"lines":50,"boot":-1,"since_minutes":None,"include_firewall":False}
    assert a.evaluate("kernel.wifi.log",args,gated=("boot",)).allowed
    assert a.evaluate("kernel.wifi.log",{**args,"boot":-4},gated=("boot",)).reason=="arguments_not_allowed"
    assert a.evaluate("kernel.wifi.log",{**args,"include_firewall":True},gated=("include_firewall",)).reason=="unconstrained_argument:include_firewall"


def test_journal_query_window_args_are_not_gated():
    # Without -b/--since, journal.query already reads every boot: boot/since_minutes only narrow it.
    ops=packs.default_registry().operations
    assert not any(p.gated for p in ops["journal.query"].params)
    assert [p.name for p in ops["kernel.wifi.log"].params if p.gated]==["boot","include_firewall"]


def test_forced_rescan_requires_an_explicit_grant():
    assert [p.name for p in packs.default_registry().operations["wifi.scan"].params if p.gated]==["rescan"]
    a=Authority({"apiVersion":"mcp-remote-sudo/v1","kind":"TaskAuthority","metadata":{"id":"g"},
        "binding":{"agent":"a","session":"s","host":"h"},
        "lifetime":{"notAfter":"2099-01-01T00:00:00Z","renewable":False,"expansion":"prohibited"},
        "allow":[{"tool":"wifi.scan"}]})
    assert a.evaluate("wifi.scan",{"rescan":False}).allowed
    assert a.evaluate("wifi.scan",{"rescan":True},gated=("rescan",)).reason=="unconstrained_argument:rescan"
