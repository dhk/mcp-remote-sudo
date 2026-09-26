from __future__ import annotations
import re, subprocess
from typing import Sequence
UNIT=re.compile(r"^[A-Za-z0-9_.@:-]+$")
def run(argv: Sequence[str], timeout: int=15)->dict:
    p=subprocess.run(list(argv),capture_output=True,text=True,timeout=timeout,check=False)
    return {"argv":list(argv),"returncode":p.returncode,"stdout":p.stdout[-20000:],"stderr":p.stderr[-5000:]}
def system_info()->dict: return {"uname":run(["uname","-a"]),"os_release":run(["cat","/etc/os-release"])}
def network_status()->dict: return {"ip":run(["ip","-json","address"]),"routes":run(["ip","-json","route"])}
def wifi_status()->dict: return {"nmcli":run(["nmcli","-t","-f","DEVICE,TYPE,STATE,CONNECTION","device","status"])}
def wifi_scan()->dict: return {"nmcli":run(["nmcli","-t","-f","SSID,BSSID,SIGNAL,SECURITY","device","wifi","list"])}
def systemd_status(unit:str)->dict:
    if not UNIT.fullmatch(unit): raise ValueError("invalid systemd unit")
    return {"systemctl":run(["systemctl","show",unit,"--no-pager"])}
def journal_query(unit:str,lines:int=100)->dict:
    if not UNIT.fullmatch(unit): raise ValueError("invalid systemd unit")
    if not isinstance(lines,int) or lines<1 or lines>500: raise ValueError("lines must be between 1 and 500")
    return {"journalctl":run(["journalctl","-u",unit,"-n",str(lines),"--no-pager","-o","short-iso"])}
