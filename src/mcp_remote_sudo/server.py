from __future__ import annotations
import argparse, inspect, os, socket
from typing import Any, Callable, Sequence
from mcp.server.fastmcp import FastMCP
from . import packs
from .authority import Authority, Decision
from .receipts import ReceiptWriter

class Runtime:
    def __init__(self,authority:Authority,receipts:ReceiptWriter,*,agent:str,session:str,host:str):
        self.authority=authority; self.receipts=receipts; self.agent=agent; self.session=session; self.host=host
        binding=authority.check_binding(agent=agent,session=session,host=host)
        if not binding.allowed: raise ValueError(binding.reason)
    def invoke(self,tool:str,args:dict[str,Any],fn:Callable[...,Any],gated:Sequence[str]=())->Any:
        d=self.authority.evaluate(tool,args)
        if d.allowed:
            unpinned=[g for g in gated if g not in ((d.rule or {}).get("args") or {})]
            if unpinned: d=Decision(False,f"unconstrained_argument:{unpinned[0]}",d.rule)
        base={"manifest_id":self.authority.manifest["metadata"]["id"],"manifest_version":self.authority.manifest["metadata"].get("version"),"manifest_hash":self.authority.manifest_hash,"agent":self.agent,"session":self.session,"host":self.host,"tool":tool,"arguments":args,"decision":"allow" if d.allowed else "deny","reason":d.reason}
        if not d.allowed:
            self.receipts.write({**base,"result":"denied"}); raise PermissionError(f"{tool}: {d.reason}")
        try: result=fn(**args)
        except Exception as exc:
            self.receipts.write({**base,"result":"failed","error":type(exc).__name__}); raise
        self.receipts.write({**base,"result":"success"}); return result

def _tool_function(runtime:Runtime, op:packs.Operation)->Callable[...,Any]:
    """An MCP tool callable whose typed signature comes from the pack declaration."""
    def call(**supplied:Any)->dict:
        args=op.normalize(supplied); gated=op.gated_in_use(args)
        return runtime.invoke(op.name,args,op.adapter,**({"gated":gated} if gated else {}))
    params=[inspect.Parameter(p.name,inspect.Parameter.KEYWORD_ONLY,annotation=p.type,
                              default=inspect.Parameter.empty if p.default is packs.REQUIRED else p.default) for p in op.params]
    call.__name__=op.tool; call.__doc__=op.description
    call.__signature__=inspect.Signature(params,return_annotation=dict)  # type: ignore[attr-defined]
    return call

def build_server(runtime:Runtime, *, port:int=8765, registry:packs.Registry|None=None)->FastMCP:
    mcp=FastMCP("mcp-remote-sudo",host="127.0.0.1",port=port); registry=registry or packs.default_registry()
    # Fail closed: every allowed operation must be provided by an installed pack.
    for op in registry.require(runtime.authority.allowed_tools):
        mcp.add_tool(_tool_function(runtime,op),name=op.tool,description=op.description)
    return mcp

def main()->None:
    p=argparse.ArgumentParser(); p.add_argument("--manifest",required=True); p.add_argument("--agent",required=True); p.add_argument("--session",required=True); p.add_argument("--host",default=socket.gethostname()); p.add_argument("--receipts",default=os.environ.get("MCP_REMOTE_SUDO_RECEIPTS","./receipts.jsonl")); p.add_argument("--port",type=int,default=8765); a=p.parse_args()
    authority=Authority.load(a.manifest); runtime=Runtime(authority,ReceiptWriter(a.receipts),agent=a.agent,session=a.session,host=a.host)
    if not 1 <= a.port <= 65535: p.error("--port must be between 1 and 65535")
    build_server(runtime,port=a.port).run(transport="streamable-http")
if __name__=="__main__": main()
