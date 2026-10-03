from __future__ import annotations
import re, subprocess
from pathlib import Path
from typing import Sequence

UNIT=re.compile(r"^[A-Za-z0-9_.@:-]+$")
MODULE=re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
TARGET=re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}$")
WIFI_LOG_TERMS=("wl","wlp","wlan","wifi","wi-fi","broadcom","cfg80211","80211","networkmanager")

def run(argv: Sequence[str], timeout: int=15)->dict:
    p=subprocess.run(list(argv),capture_output=True,text=True,timeout=timeout,check=False)
    return {"argv":list(argv),"returncode":p.returncode,"stdout":p.stdout[-20000:],"stderr":p.stderr[-5000:]}

def system_info()->dict: return {"uname":run(["uname","-a"]),"os_release":run(["cat","/etc/os-release"])}
def network_status()->dict: return {"ip":run(["ip","-json","address"]),"routes":run(["ip","-json","route"])}
def wifi_status()->dict: return {"nmcli":run(["nmcli","-t","-f","DEVICE,TYPE,STATE,CONNECTION","device","status"])}
def wifi_scan()->dict: return {"nmcli":run(["nmcli","-t","-f","SSID,BSSID,SIGNAL,SECURITY","device","wifi","list"])}

def wifi_driver_status(module:str)->dict:
    if not MODULE.fullmatch(module): raise ValueError("invalid kernel module")
    return {
        "kernel":run(["uname","-r"]),
        "loaded":(Path("/sys/module") / module).is_dir(),
        "modinfo":run(["modinfo","--",module]),
    }

def connectivity_probe(target:str,count:int=4)->dict:
    if not TARGET.fullmatch(target): raise ValueError("invalid probe target")
    if not isinstance(count,int) or isinstance(count,bool) or count<1 or count>10:
        raise ValueError("count must be between 1 and 10")
    return {"ping":run(["ping","-n","-c",str(count),"--",target],timeout=min(15, count*2+3))}

def kernel_wifi_log(lines:int=100)->dict:
    if not isinstance(lines,int) or isinstance(lines,bool) or lines<1 or lines>500:
        raise ValueError("lines must be between 1 and 500")
    result=run(["journalctl","-k","-b","-n",str(lines),"--no-pager","-o","short-iso"])
    filtered="\n".join(
        line for line in result["stdout"].splitlines()
        if any(term in line.lower() for term in WIFI_LOG_TERMS)
    )
    return {"journalctl":{**result,"stdout":filtered}}

def systemd_status(unit:str)->dict:
    if not UNIT.fullmatch(unit): raise ValueError("invalid systemd unit")
    return {"systemctl":run(["systemctl","show",unit,"--no-pager"])}

def journal_query(unit:str,lines:int=100)->dict:
    if not UNIT.fullmatch(unit): raise ValueError("invalid systemd unit")
    if not isinstance(lines,int) or isinstance(lines,bool) or lines<1 or lines>500: raise ValueError("lines must be between 1 and 500")
    return {"journalctl":run(["journalctl","-u",unit,"-n",str(lines),"--no-pager","-o","short-iso"])}
