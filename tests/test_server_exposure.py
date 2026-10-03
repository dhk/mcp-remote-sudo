import asyncio

from mcp_remote_sudo.authority import Authority
from mcp_remote_sudo.server import build_server


class StubRuntime:
    def __init__(self, allowed):
        self.authority=Authority({
            "apiVersion":"mcp-remote-sudo/v1",
            "kind":"TaskAuthority",
            "metadata":{"id":"server-exposure-test","version":1},
            "binding":{"agent":"a","session":"s","host":"h"},
            "lifetime":{"notAfter":"2099-01-01T00:00:00Z","renewable":False,"expansion":"prohibited"},
            "allow":[{"tool":tool} for tool in allowed],
            "deny":[],
            "receipts":{"required":True},
        })

    def invoke(self,tool,args,fn):
        return fn(**args)


def tool_names(server):
    return {tool.name for tool in asyncio.run(server.list_tools())}


def test_wifi_diagnostic_tools_are_exposed_when_allowed():
    server=build_server(StubRuntime({"wifi.driver.status","kernel.wifi.log","network.probe"}))
    names=tool_names(server)
    assert {"wifi_driver_status","kernel_wifi_log","connectivity_probe"} <= names


def test_wifi_diagnostic_tools_are_absent_when_not_allowed():
    server=build_server(StubRuntime({"wifi.status","wifi.scan"}))
    names=tool_names(server)
    assert "wifi_driver_status" not in names
    assert "kernel_wifi_log" not in names
    assert "connectivity_probe" not in names
