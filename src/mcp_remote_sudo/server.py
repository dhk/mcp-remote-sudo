from __future__ import annotations
import argparse, asyncio, functools, inspect, json, logging, os, signal, socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence
from mcp.server.fastmcp import FastMCP
from . import packs
from .authority import Authority
from .receipts import ReceiptWriter

class Runtime:
    def __init__(self,authority:Authority,receipts:ReceiptWriter,*,agent:str,session:str,host:str):
        self.authority=authority; self.receipts=receipts; self.agent=agent; self.session=session; self.host=host
        binding=authority.check_binding(agent=agent,session=session,host=host)
        if not binding.allowed: raise ValueError(binding.reason)
    def invoke(self,tool:str,args:dict[str,Any],fn:Callable[...,Any],gated:Sequence[str]=())->Any:
        d=self.authority.evaluate(tool,args,gated=tuple(gated))
        base={"manifest_id":self.authority.manifest["metadata"]["id"],"manifest_version":self.authority.manifest["metadata"].get("version"),"manifest_hash":self.authority.manifest_hash,"agent":self.agent,"session":self.session,"host":self.host,"tool":tool,"arguments":args,"decision":"allow" if d.allowed else "deny","reason":d.reason}
        if not d.allowed:
            self.receipts.write({**base,"result":"denied"}); raise PermissionError(f"{tool}: {d.reason}")
        try: result=fn(**args)
        except Exception as exc:
            self.receipts.write({**base,"result":"failed","error":type(exc).__name__}); raise
        self.receipts.write({**base,"result":"success"}); return result

def _tool_function(runtime:Runtime, op:packs.Operation)->Callable[...,Any]:
    """An MCP tool callable whose typed signature comes from the pack declaration."""
    adapter=functools.partial(op.adapter,runtime) if op.needs_runtime else op.adapter
    def call(**supplied:Any)->dict:
        args=op.normalize(supplied); gated=op.gated_in_use(args)
        return runtime.invoke(op.name,args,adapter,**({"gated":gated} if gated else {}))
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

log=logging.getLogger("mcp_remote_sudo")

class AuthorityReloader:
    """Re-reads the manifest (on SIGHUP) and swaps the active authority and exposed tools without a restart.
    A manifest that fails validation, binding or pack checks is rejected and the previous authority stays active."""
    def __init__(self,mcp:FastMCP,runtime:Runtime,registry:packs.Registry,manifest_path:str|Path,status_path:str|Path|None=None):
        self.mcp=mcp; self.runtime=runtime; self.registry=registry; self.manifest_path=Path(manifest_path)
        self.status_path=Path(status_path) if status_path else None
        self.exposed={op.tool:op for op in registry.require(runtime.authority.allowed_tools)}
    def _receipt(self,authority:Authority,result:str,**extra:Any)->None:
        md=authority.manifest["metadata"]
        self.runtime.receipts.write({"manifest_id":md["id"],"manifest_version":md.get("version"),"manifest_hash":authority.manifest_hash,
            "agent":self.runtime.agent,"session":self.runtime.session,"host":self.runtime.host,"tool":"authority.reload",
            "arguments":{},"decision":"operator","result":result,**extra})
    def write_status(self,ok:bool,error:str|None=None)->dict:
        a=self.runtime.authority
        status={"ok":ok,"manifest_id":a.manifest["metadata"]["id"],"manifest_hash":a.manifest_hash,
                "not_after":a.manifest["lifetime"]["notAfter"],"tools":sorted(self.exposed),
                "at":datetime.now(timezone.utc).isoformat(),"error":error}
        if self.status_path:
            try:
                tmp=self.status_path.with_name(f".{self.status_path.name}.{os.getpid()}")
                tmp.write_text(json.dumps(status,sort_keys=True)+"\n"); tmp.chmod(0o644); os.replace(tmp,self.status_path)
            except OSError as exc: log.warning("cannot write authority status %s: %s",self.status_path,exc)
        return status
    def reload(self)->dict:
        old=self.runtime.authority
        try:
            new=Authority.load(self.manifest_path)
            binding=new.check_binding(agent=self.runtime.agent,session=self.runtime.session,host=self.runtime.host)
            if not binding.allowed: raise ValueError(binding.reason)
            ops={op.tool:op for op in self.registry.require(new.allowed_tools)}
        except Exception as exc:
            error=f"{type(exc).__name__}: {exc}"; log.error("authority reload rejected; keeping %s: %s",old.manifest_hash,error)
            self._receipt(old,"failed",error=error,rejected_manifest=str(self.manifest_path))
            return self.write_status(False,error)
        self.runtime.authority=new
        for name in set(self.exposed)-set(ops): self.mcp.remove_tool(name)
        for name in set(ops)-set(self.exposed): self.mcp.add_tool(_tool_function(self.runtime,ops[name]),name=name,description=ops[name].description)
        self.exposed=ops
        self._receipt(new,"success",previous_manifest_hash=old.manifest_hash)
        log.info("authority reloaded: %s -> %s",old.manifest_hash,new.manifest_hash)
        return self.write_status(True)

def main()->None:
    p=argparse.ArgumentParser(); p.add_argument("--manifest",required=True); p.add_argument("--agent",required=True); p.add_argument("--session",required=True); p.add_argument("--host",default=socket.gethostname()); p.add_argument("--receipts",default=os.environ.get("MCP_REMOTE_SUDO_RECEIPTS","./receipts.jsonl")); p.add_argument("--port",type=int,default=8765); p.add_argument("--state-dir",default=os.environ.get("MCP_REMOTE_SUDO_STATE_DIR","/var/lib/mcp-remote-sudo")); a=p.parse_args()
    authority=Authority.load(a.manifest); runtime=Runtime(authority,ReceiptWriter(a.receipts),agent=a.agent,session=a.session,host=a.host)
    if not 1 <= a.port <= 65535: p.error("--port must be between 1 and 65535")
    registry=packs.default_registry(); mcp=build_server(runtime,port=a.port,registry=registry)
    reloader=AuthorityReloader(mcp,runtime,registry,a.manifest,Path(a.state_dir)/"authority-status.json"); reloader.write_status(True)
    async def serve()->None:
        # Reload runs as an event-loop callback, so tool changes never interleave with request handling.
        asyncio.get_running_loop().add_signal_handler(signal.SIGHUP,reloader.reload)
        await mcp.run_streamable_http_async()
    asyncio.run(serve())
if __name__=="__main__": main()
