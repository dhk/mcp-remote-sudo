from __future__ import annotations
import re, subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

UNIT=re.compile(r"^[A-Za-z0-9_.@:-]+$")
MODULE=re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
TARGET=re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}$")

def run(argv: Sequence[str], timeout: int=15, max_stdout: int=20000)->dict:
    p=subprocess.run(list(argv),capture_output=True,text=True,timeout=timeout,check=False)
    out=p.stdout; truncated=len(out)>max_stdout
    if truncated: out=out[-max_stdout:]
    return {"argv":list(argv),"returncode":p.returncode,"stdout":out,"stderr":p.stderr[-5000:],**({"truncated":True} if truncated else {})}

def system_info()->dict: return {"uname":run(["uname","-a"]),"os_release":run(["cat","/etc/os-release"])}
def network_status()->dict: return {"ip":run(["ip","-json","address"]),"routes":run(["ip","-json","route"])}
def wifi_status()->dict: return {"nmcli":run(["nmcli","-t","-f","DEVICE,TYPE,STATE,CONNECTION","device","status"])}
def wifi_scan(rescan:bool=False)->dict:
    """Visible networks. rescan=True forces a fresh scan (proves results are not cached); default lets NetworkManager decide."""
    if not isinstance(rescan,bool): raise ValueError("rescan must be a boolean")
    return {"nmcli":run(["nmcli","-t","-f","SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY","device","wifi","list",*(["--rescan","yes"] if rescan else [])],timeout=30)}

def wifi_link()->dict:
    """The associated access point(s): BSSID, channel, frequency, rate, signal. Never triggers a scan."""
    result=run(["nmcli","-t","-f","IN-USE,DEVICE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY","device","wifi","list","--rescan","no"])
    active=[line for line in result["stdout"].splitlines() if line.startswith("*:")]
    return {"nmcli":{**result,"stdout":"\n".join(active)},"associated":bool(active)}

SYSFS=Path("/sys")
PCI_ADDRESS=re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]$")

def _read_sysfs(path:Path)->str|None:
    try: return path.read_text().strip()
    except OSError: return None

def wifi_driver_status(module:str)->dict:
    """Module state from sysfs. modinfo is not used: ProtectKernelModules= hides /usr/lib/modules from the service."""
    if not MODULE.fullmatch(module): raise ValueError("invalid kernel module")
    mod=SYSFS/"module"/module
    devices=sorted(d.name for d in (SYSFS/"bus"/"pci"/"drivers"/module).glob("*") if PCI_ADDRESS.fullmatch(d.name))
    interfaces=sorted(n.name for n in (SYSFS/"class"/"net").glob("*") if (n/"device"/"driver").is_symlink()
                      and (n/"device"/"driver").resolve().name==module)
    return {
        "kernel":run(["uname","-r"]),
        "loaded":mod.is_dir(),
        "module":{k:_read_sysfs(mod/k) for k in ("version","srcversion","taint","refcnt","initstate")},
        "pci_devices":devices,
        "interfaces":interfaces,
    }

def connectivity_probe(target:str,count:int=4)->dict:
    if not TARGET.fullmatch(target): raise ValueError("invalid probe target")
    if not isinstance(count,int) or isinstance(count,bool) or count<1 or count>10:
        raise ValueError("count must be between 1 and 10")
    return {"ping":run(["ping","-n","-c",str(count),"--",target],timeout=min(15, count*2+3))}

# Driver/stack terms matched on token boundaries ("wl" must not match inside "owl" or "IN=wlp2s0"-only noise).
WIFI_LOG_PATTERN=re.compile(
    # Distinctive Wi-Fi stack and driver names, safe as substrings because each contains a non-hex letter, so hex
    # addresses and stack offsets can't match (cfg80211/mac80211/ieee80211/nl80211, iwlwifi,
    # rtlwifi, mwifiex, brcmfmac/brcmsmac, ath9k/10k/11k/12k, mt76/mt79xx, rtw88/89, rtl8xxxu, r8188eu, rt2x00/rt2800).
    r"(?:cfg|mac|ieee|nl)80211|wifi|wi-fi|wpa_supplicant|networkmanager|brcmf|brcmsmac|ath\d+k|mt7[69]|rtw8|rtl8xxxu|r8188eu"
    r"|rt2x00|rt2800|rt2500|rt61pci|rt73usb|carl9170|wcn36xx|zd1211|iwlmvm|iwldvm"
    # Short or ambiguous tokens need boundaries: the wl and b43 drivers, wl*/wlan* interface names, generic `ath:` lines and
    # Realtek Wi-Fi models (rtl8723be/bs, rtl8821ae, rtl8188eu/cu/fu, rtl8192se) without matching Ethernet RTL8168h/rtl8153.
    r"|(?<![a-z0-9])(?:wl|wl[a-z0-9]\w*|ath|b43(?:legacy)?|rtl8\d{3}(?:[a-e]e|[cef]u|se|bs))(?![a-z0-9])")
# Netfilter/UFW log lines carry the interface name but are never driver evidence.
FIREWALL_LOG_PATTERN=re.compile(r"\[UFW [A-Z ]+\]|\bIN=\S* OUT=\S*")
KERNEL_LOG_SCAN_LINES=5000
KERNEL_LOG_SCAN_CHARS=4_000_000   # ~5000 lines x 800 chars: the whole window reaches the filter

def kernel_wifi_log(lines:int=100,boot:int=0,since_minutes:int|None=None,include_firewall:bool=False)->dict:
    _int_in(lines,1,500,"lines")
    if not isinstance(include_firewall,bool): raise ValueError("include_firewall must be a boolean")
    # Scan a bounded window, filter, then return at most `lines` matches (newest last).
    result=run(["journalctl","-k","-n",str(KERNEL_LOG_SCAN_LINES),*journal_window(boot,since_minutes),"--no-pager","-o","short-iso"],
               max_stdout=KERNEL_LOG_SCAN_CHARS)
    scanned=result["stdout"].splitlines()
    if result.get("truncated") and scanned: scanned=scanned[1:]   # drop the partial first line
    matched=[line for line in scanned
             if WIFI_LOG_PATTERN.search(line.lower()) and (include_firewall or not FIREWALL_LOG_PATTERN.search(line))]
    return {"journalctl":{**result,"stdout":"\n".join(matched[-lines:]),"matched":len(matched),"returned":min(len(matched),lines)}}

def systemd_status(unit:str)->dict:
    if not UNIT.fullmatch(unit): raise ValueError("invalid systemd unit")
    return {"systemctl":run(["systemctl","show",unit,"--no-pager"])}

MAX_BOOT_OFFSET=1000
MAX_SINCE_MINUTES=7*24*60

def _int_in(value,lo,hi,what)->int:
    if not isinstance(value,int) or isinstance(value,bool) or value<lo or value>hi: raise ValueError(f"{what} must be between {lo} and {hi}")
    return value

def journal_window(boot:int|None=None,since_minutes:int|None=None)->list[str]:
    """journalctl arguments selecting a boot (0 = current, -1 = previous, ...) and/or the last N minutes."""
    argv=[]
    if boot is not None: argv+=["-b",str(_int_in(boot,-MAX_BOOT_OFFSET,0,"boot"))]
    if since_minutes is not None:
        start=datetime.now(timezone.utc)-timedelta(minutes=_int_in(since_minutes,1,MAX_SINCE_MINUTES,"since_minutes"))
        argv+=["--since",start.strftime("%Y-%m-%d %H:%M:%S UTC")]
    return argv

def journal_query(unit:str,lines:int=100,boot:int|None=None,since_minutes:int|None=None)->dict:
    if not UNIT.fullmatch(unit): raise ValueError("invalid systemd unit")
    _int_in(lines,1,500,"lines")
    return {"journalctl":run(["journalctl","-u",unit,"-n",str(lines),*journal_window(boot,since_minutes),"--no-pager","-o","short-iso"])}

def journal_boots(limit:int=20)->dict:
    _int_in(limit,1,100,"limit")
    result=run(["journalctl","--list-boots","--no-pager"])
    rows=result["stdout"].splitlines()
    header,boots=(rows[:1],rows[1:]) if rows and rows[0].lstrip().startswith("IDX") else ([],rows)
    return {"journalctl":{**result,"stdout":"\n".join(header+boots[-limit:])}}
