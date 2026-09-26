from __future__ import annotations
import argparse, os, socket
from typing import Any, Callable
from mcp.server.fastmcp import FastMCP
from . import adapters
from .authority import Authority
from .receipts import ReceiptWriter

class Runtime:
    def __init__(self,authority:Authority,receipts:ReceiptWriter,*,agent:str,session:str,host:str):
        self.authority=authority; self.receipts=receipts; self.agent=agent; self.session=session; self.host=host
        binding=authority.check_binding(agent=agent,session=session,host=host)
        if not binding.allowed: raise ValueError(binding.reason)
    def invoke(self,tool:str,args:dict[str,Any],fn:Callable[...,Any])->Any:
        d=self.authority.evaluate(tool,args)
        base={"manifest_id":self.authority.manifest["metadata"]["id"],"manifest_version":self.authority.manifest["metadata"].get("version"),"manifest_hash":self.authority.manifest_hash,"agent":self.agent,"session":self.session,"host":self.host,"tool":tool,"arguments":args,"decision":"allow" if d.allowed else "deny","reason":d.reason}
        if not d.allowed:
            self.receipts.write({**base,"result":"denied"}); raise PermissionError(f"{tool}: {d.reason}")
        try: result=fn(**args)
        except Exception as exc:
            self.receipts.write({**base,"result":"failed","error":type(exc).__name__}); raise
        self.receipts.write({**base,"result":"success"}); return result

def build_server(runtime:Runtime)->FastMCP:
    mcp=FastMCP("mcp-remote-sudo",host="127.0.0.1",port=8765); allowed=runtime.authority.allowed_tools
    if "system.info" in allowed:
        @mcp.tool(name="system_info")
        def system_info()->dict: return runtime.invoke("system.info",{},adapters.system_info)
    if "network.status" in allowed:
        @mcp.tool(name="network_status")
        def network_status()->dict: return runtime.invoke("network.status",{},adapters.network_status)
    if "wifi.status" in allowed:
        @mcp.tool(name="wifi_status")
        def wifi_status()->dict: return runtime.invoke("wifi.status",{},adapters.wifi_status)
    if "wifi.scan" in allowed:
        @mcp.tool(name="wifi_scan")
        def wifi_scan()->dict: return runtime.invoke("wifi.scan",{},adapters.wifi_scan)
    if "systemd.status" in allowed:
        @mcp.tool(name="systemd_status")
        def systemd_status(unit:str)->dict: return runtime.invoke("systemd.status",{"unit":unit},adapters.systemd_status)
    if "journal.query" in allowed:
        @mcp.tool(name="journal_query")
        def journal_query(unit:str,lines:int=100)->dict: return runtime.invoke("journal.query",{"unit":unit,"lines":lines},adapters.journal_query)
    return mcp

def main()->None:
    p=argparse.ArgumentParser(); p.add_argument("--manifest",required=True); p.add_argument("--agent",required=True); p.add_argument("--session",required=True); p.add_argument("--host",default=socket.gethostname()); p.add_argument("--receipts",default=os.environ.get("MCP_REMOTE_SUDO_RECEIPTS","./receipts.jsonl")); a=p.parse_args()
    authority=Authority.load(a.manifest); runtime=Runtime(authority,ReceiptWriter(a.receipts),agent=a.agent,session=a.session,host=a.host)
    build_server(runtime).run(transport="streamable-http")
if __name__=="__main__": main()
