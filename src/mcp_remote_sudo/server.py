from __future__ import annotations
# Installed before the heavy imports below: Python's default SIGHUP action terminates the process, and systemd treats
# that as a clean exit (no restart). A reload requested while the service is still starting is recorded here and
# applied once the event-loop handler is in place (see main()).
import signal as _signal, threading as _threading
_EARLY_HUP:list[int]=[]
if _threading.current_thread() is _threading.main_thread():   # signal handlers can only be set on the main thread
    _signal.signal(_signal.SIGHUP,lambda signum,frame:_EARLY_HUP.append(signum))
import argparse, asyncio, functools, hashlib, inspect, json, logging, os, signal, socket, sys
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence
from mcp.server.fastmcp import FastMCP
from . import packs
from .authority import Authority
from .receipts import ReceiptWriter

class Runtime:
    """session=None means the session comes from the active manifest's binding (minted per grant by the admin);
    a fixed session (legacy --session) must match every manifest."""
    def __init__(self,authority:Authority,receipts:ReceiptWriter,*,agent:str,session:str|None,host:str):
        self.receipts=receipts; self.agent=agent; self.host=host; self.fixed_session=session
        self.check(authority); self.authority=authority
    @property
    def session(self)->str: return self.fixed_session or self.authority.manifest["binding"]["session"]
    @property
    def session_mode(self)->str: return "fixed" if self.fixed_session else "manifest"
    def check(self,authority:Authority)->None:
        session=self.fixed_session or authority.manifest["binding"]["session"]
        binding=authority.check_binding(agent=self.agent,session=session,host=self.host)
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
    def write_status(self,ok:bool,error:str|None=None,attempted_hash:str|None=None,attempted_file_sha256:str|None=None)->dict:
        a=self.runtime.authority
        # attempted_hash: the manifest this status is about (None when the file couldn't even be parsed), so the
        # admin never mistakes a rejection of some other manifest for a verdict on its own grant.
        status={"ok":ok,"manifest_id":a.manifest["metadata"]["id"],"manifest_hash":a.manifest_hash,
                "attempted_hash":attempted_hash if attempted_hash is not None or not ok else a.manifest_hash,
                "attempted_file_sha256":attempted_file_sha256,
                "not_after":a.manifest["lifetime"]["notAfter"],"tools":sorted(self.exposed),
                "session":self.runtime.session,"session_mode":self.runtime.session_mode,
                "packs":self.registry.describe(),
                "at":datetime.now(timezone.utc).isoformat(),"error":error}
        if self.status_path:
            try:
                tmp=self.status_path.with_name(f".{self.status_path.name}.{os.getpid()}")
                tmp.write_text(json.dumps(status,sort_keys=True)+"\n"); tmp.chmod(0o644); os.replace(tmp,self.status_path)
            except OSError as exc: log.warning("cannot write authority status %s: %s",self.status_path,exc)
        return status
    def reload(self)->dict:
        old=self.runtime.authority; attempted:str|None=None; file_sha:str|None=None
        try:
            data=self.manifest_path.read_bytes(); file_sha=hashlib.sha256(data).hexdigest()
            parsed=yaml.safe_load(data)
            if not isinstance(parsed,dict): raise ValueError("manifest must be a mapping")
            new=Authority(parsed); attempted=new.manifest_hash
            self.runtime.check(new)
            ops={op.tool:op for op in self.registry.require(new.allowed_tools)}
        except Exception as exc:
            error=f"{type(exc).__name__}: {exc}"; log.error("authority reload rejected; keeping %s: %s",old.manifest_hash,error)
            self._receipt(old,"failed",error=error,rejected_manifest=str(self.manifest_path))
            return self.write_status(False,error,attempted_hash=attempted,attempted_file_sha256=file_sha)
        old_session=self.runtime.session; self.runtime.authority=new
        for name in set(self.exposed)-set(ops): self.mcp.remove_tool(name)
        for name in set(ops)-set(self.exposed): self.mcp.add_tool(_tool_function(self.runtime,ops[name]),name=name,description=ops[name].description)
        self.exposed=ops
        self._receipt(new,"success",previous_manifest_hash=old.manifest_hash,previous_session=old_session)
        log.info("authority reloaded: %s -> %s",old.manifest_hash,new.manifest_hash)
        return self.write_status(True,attempted_hash=new.manifest_hash,attempted_file_sha256=file_sha)

def main()->None:
    p=argparse.ArgumentParser(); p.add_argument("--manifest",required=True); p.add_argument("--agent",required=True); p.add_argument("--session",default=None,help="legacy fixed session; omit to take the session from the active manifest (minted per grant)"); p.add_argument("--host",default=socket.gethostname()); p.add_argument("--receipts",default=os.environ.get("MCP_REMOTE_SUDO_RECEIPTS","./receipts.jsonl")); p.add_argument("--port",type=int,default=8765); p.add_argument("--state-dir",default=os.environ.get("MCP_REMOTE_SUDO_STATE_DIR","/var/lib/mcp-remote-sudo")); p.add_argument("--packs-dir",default=None,help="external Task Packs installed with pip --target; appended (lowest priority) to sys.path"); a=p.parse_args()
    if a.packs_dir and os.path.isdir(a.packs_dir): sys.path.append(a.packs_dir)  # append, never prepend: packs must not shadow core modules
    authority=Authority.load(a.manifest); runtime=Runtime(authority,ReceiptWriter(a.receipts),agent=a.agent,session=a.session,host=a.host)
    if not 1 <= a.port <= 65535: p.error("--port must be between 1 and 65535")
    registry=packs.default_registry(); mcp=build_server(runtime,port=a.port,registry=registry)
    reloader=AuthorityReloader(mcp,runtime,registry,a.manifest,Path(a.state_dir)/"authority-status.json"); reloader.write_status(True)
    async def serve()->None:
        # Reload runs as an event-loop callback, so tool changes never interleave with request handling.
        asyncio.get_running_loop().add_signal_handler(signal.SIGHUP,reloader.reload)
        if _EARLY_HUP: reloader.reload()
        await mcp.run_streamable_http_async()
    asyncio.run(serve())
if __name__=="__main__": main()
