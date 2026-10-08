import pytest
from mcp_remote_sudo import adapters


def make_sysfs(root):
    mod=root/"module"/"wl"; mod.mkdir(parents=True)
    (mod/"version").write_text("6.30.223.271\n"); (mod/"srcversion").write_text("ABC123\n")
    (mod/"taint").write_text("POE\n"); (mod/"refcnt").write_text("0\n"); (mod/"initstate").write_text("live\n")
    drv=root/"bus"/"pci"/"drivers"/"wl"; drv.mkdir(parents=True)
    dev=root/"devices"/"pci0000:00"/"0000:02:00.0"; dev.mkdir(parents=True)
    (dev/"driver").symlink_to(drv)
    (drv/"0000:02:00.0").symlink_to(dev); (drv/"bind").write_text(""); (drv/"module").mkdir()
    net=root/"class"/"net"; net.mkdir(parents=True)
    (net/"wlp2s0").mkdir(); (net/"wlp2s0"/"device").symlink_to(dev)
    (net/"lo").mkdir()


def test_wifi_driver_status_reads_sysfs_not_modinfo(monkeypatch, tmp_path):
    make_sysfs(tmp_path); monkeypatch.setattr(adapters,"SYSFS",tmp_path)
    calls=[]
    monkeypatch.setattr(adapters,"run",lambda argv,timeout=15: calls.append(list(argv)) or {"argv":list(argv),"returncode":0,"stdout":"6.8.0-142-generic\n","stderr":""})
    result=adapters.wifi_driver_status("wl")
    assert calls==[["uname","-r"]]
    assert result["loaded"] is True
    assert result["module"]=={"version":"6.30.223.271","srcversion":"ABC123","taint":"POE","refcnt":"0","initstate":"live"}
    assert result["pci_devices"]==["0000:02:00.0"] and result["interfaces"]==["wlp2s0"]


def test_wifi_driver_status_absent_module_and_validation(monkeypatch, tmp_path):
    monkeypatch.setattr(adapters,"SYSFS",tmp_path)
    monkeypatch.setattr(adapters,"run",lambda argv,timeout=15: {"argv":list(argv),"returncode":0,"stdout":"","stderr":""})
    result=adapters.wifi_driver_status("b43")
    assert result["loaded"] is False and result["module"]["version"] is None and result["interfaces"]==[]
    for bad in ("wl;reboot","--help","-wl","../wl"):
        with pytest.raises(ValueError):
            adapters.wifi_driver_status(bad)


def test_wifi_scan_rescan_is_explicit(monkeypatch):
    calls=[]
    monkeypatch.setattr(adapters,"run",lambda argv,timeout=15: calls.append(list(argv)) or {"argv":list(argv),"returncode":0,"stdout":"","stderr":""})
    adapters.wifi_scan(); adapters.wifi_scan(rescan=True)
    assert "--rescan" not in calls[0] and calls[1][-2:]==["--rescan","yes"]
    with pytest.raises(ValueError):
        adapters.wifi_scan(rescan="yes")


def test_wifi_link_reports_only_the_associated_ap(monkeypatch):
    out="*:wlp2s0:DHKs Network:60\\:5F\\:8D\\:46\\:31\\:07:149:5745 MHz:270 Mbit/s:100:WPA2\n :wlp2s0:DHKs Network:60\\:5F\\:8D\\:46\\:31\\:06:11:2462 MHz:130 Mbit/s:100:WPA2\n"
    monkeypatch.setattr(adapters,"run",lambda argv,timeout=15: {"argv":list(argv),"returncode":0,"stdout":out,"stderr":""})
    result=adapters.wifi_link()
    assert result["associated"] is True and result["nmcli"]["stdout"].count("\n")==0 and ":149:5745 MHz:" in result["nmcli"]["stdout"]
    assert result["nmcli"]["argv"][-2:]==["--rescan","no"]


def test_connectivity_probe_is_bounded_and_argv_only(monkeypatch):
    calls=[]
    monkeypatch.setattr(adapters,"run",lambda argv,timeout=15: calls.append((list(argv),timeout)) or {"argv":list(argv),"returncode":0,"stdout":"","stderr":""})
    adapters.connectivity_probe("1.1.1.1",4)
    assert calls == [(["ping","-n","-c","4","--","1.1.1.1"],11)]
    for bad in ("1.1.1.1;reboot","$(id)","example.com && id"):
        with pytest.raises(ValueError):
            adapters.connectivity_probe(bad,4)
    with pytest.raises(ValueError):
        adapters.connectivity_probe("1.1.1.1",11)
    with pytest.raises(ValueError):
        adapters.connectivity_probe("1.1.1.1",True)


LOBSTER_KERNEL_LOG = "\n".join([
    "2026-09-30T02:41:20+00:00 lobster kernel: [UFW BLOCK] IN=wlp2s0 OUT= MAC=01:00:5e:00:00:fb SRC=192.168.7.53 DST=224.0.0.251 LEN=32 PROTO=2",
    "2026-09-30T02:41:24+00:00 lobster kernel: ERROR @wl_notify_scan_status : ",
    "2026-09-30T02:41:24+00:00 lobster kernel: wlp2s0 Scan_results error (-22)",
    "2026-09-30T02:41:30+00:00 lobster kernel: [UFW BLOCK] IN=wlp2s0 OUT= MAC=88:53:95:2c:d7:ad SRC=192.168.7.194 DST=192.168.7.86 PROTO=UDP",
    "2026-09-30T02:41:31+00:00 lobster kernel: owl driver unrelated",
    "2026-09-30T02:41:32+00:00 lobster kernel: perf: interrupt took too long",
    "2026-09-30T02:41:33+00:00 lobster kernel: cfg80211: Loading compiled-in X.509 certificates",
])


def fake_journal(monkeypatch, stdout, seen=None):
    def fake_run(argv,timeout=15,**kw):
        if seen is not None: seen.append(list(argv))
        return {"argv":list(argv),"returncode":0,"stdout":stdout,"stderr":""}
    monkeypatch.setattr(adapters,"run",fake_run)


def test_kernel_wifi_log_excludes_firewall_noise_and_substring_matches(monkeypatch):
    seen=[]; fake_journal(monkeypatch, LOBSTER_KERNEL_LOG, seen)
    out=adapters.kernel_wifi_log(100)["journalctl"]
    assert out["stdout"].splitlines()==[LOBSTER_KERNEL_LOG.splitlines()[i] for i in (1,2,6)]
    assert out["matched"]==3 and out["returned"]==3
    assert seen==[["journalctl","-k","-n","5000","-b","0","--no-pager","-o","short-iso"]]


def test_kernel_wifi_log_can_include_firewall_lines(monkeypatch):
    fake_journal(monkeypatch, LOBSTER_KERNEL_LOG)
    assert adapters.kernel_wifi_log(100,include_firewall=True)["journalctl"]["matched"]==5


def test_kernel_wifi_log_limits_after_filtering_and_selects_boot(monkeypatch):
    seen=[]; fake_journal(monkeypatch, LOBSTER_KERNEL_LOG, seen)
    out=adapters.kernel_wifi_log(1,boot=-1)["journalctl"]
    assert out["stdout"].endswith("cfg80211: Loading compiled-in X.509 certificates") and out["matched"]==3
    assert seen[0][4:6]==["-b","-1"]


def test_kernel_wifi_log_is_bounded(monkeypatch):
    fake_journal(monkeypatch, "")
    for kwargs in ({"lines":501},{"lines":True},{"lines":10,"boot":1},{"lines":10,"include_firewall":"no"}):
        with pytest.raises(ValueError):
            adapters.kernel_wifi_log(**kwargs)


def test_whole_window_reaches_the_filter_through_real_run(monkeypatch):
    """Regression (review of #57): run() used to keep only the last 20000 chars, so a UFW flood after the driver
    error pushed the evidence out before filtering."""
    from types import SimpleNamespace
    ufw=LOBSTER_KERNEL_LOG.splitlines()[0]
    stdout="\n".join([LOBSTER_KERNEL_LOG.splitlines()[1]]+[ufw]*400)+"\n"   # ~55k chars of noise after the error
    assert len(stdout)>20000
    monkeypatch.setattr(adapters.subprocess,"run",lambda argv,**kw: SimpleNamespace(returncode=0,stdout=stdout,stderr=""))
    out=adapters.kernel_wifi_log(10)["journalctl"]
    assert out["stdout"]=="2026-09-30T02:41:24+00:00 lobster kernel: ERROR @wl_notify_scan_status : " and "truncated" not in out


def test_truncated_window_drops_partial_first_line(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(adapters,"KERNEL_LOG_SCAN_CHARS",60)
    stdout="x"*50+" wlp2s0 cut\n2026 kernel: wlp2s0 Scan_results error (-22)\n"
    monkeypatch.setattr(adapters.subprocess,"run",lambda argv,**kw: SimpleNamespace(returncode=0,stdout=stdout,stderr=""))
    out=adapters.kernel_wifi_log(10)["journalctl"]
    assert out["truncated"] is True and out["stdout"]=="2026 kernel: wlp2s0 Scan_results error (-22)"


@pytest.mark.parametrize("line", [
    "kernel: iwlwifi 0000:00:14.3: Microcode SW error detected",
    "kernel: wlo1: authenticate with 60:5f:8d:46:31:07",
    "kernel: wlx001122334455: associated",
    "kernel: wlan0: deauthenticating",
    "kernel: ath10k_pci 0000:02:00.0: firmware crashed",
    "kernel: rtw88_8822ce 0000:03:00.0: failed to send h2c",
    "kernel: mt7921e 0000:04:00.0: Message 00020007 (seq 11) timeout",
    "kernel: ieee80211 phy0: Selected rate control algorithm 'minstrel_ht'",
    "kernel: nl80211: failed to send event",
    "kernel: rtl8723be 0000:02:00.0: Using firmware rtlwifi/rtl8723befw_36.bin",
    "kernel: rtl8821ae 0000:03:00.0: firmware loaded",
    "kernel: mwifiex_pcie 0000:01:00.0: info: FW download over",
    "kernel: rt2800usb 1-1:1.0: rt2x00usb_vendor_request: Error",
    "kernel: r8188eu 1-1:1.0: firmware: direct-loading",
    "kernel: ath: EEPROM regdomain: 0x0",
    "kernel: brcmfmac: brcmf_c_preinit_dcmds: Firmware: BCM4345/6",
    "kernel: ERROR @wl_notify_scan_status : ",
    "kernel: b43-phy0: Broadcom 4311 WLAN found (core revision 13)",
    "kernel: b43legacy-phy0: Loading firmware",
    "kernel: rtl8723bs: acquire FW from file:rtlwifi/rtl8723bs_nic.bin",
    "kernel: rtl8188fu 1-1:1.0: firmware loaded",
    "kernel: rt73usb 1-2:1.0: firmware error",
    "kernel: carl9170 1-1:1.0: firmware not found",
    "kernel: wcn36xx a204000.wcnss: WCNSS firmware version",
    "kernel: zd1211rw 1-1:1.0: phy0",
    "kernel: iwlmvm: queue stuck",
])
def test_common_wifi_drivers_and_interface_names_match(line):
    assert adapters.WIFI_LOG_PATTERN.search(line.lower())


@pytest.mark.parametrize("line", ["kernel: owl driver unrelated", "kernel: bowling ball", "kernel: newly attached",
                                  "kernel: r8169 0000:03:00.0 eth0: RTL8168h/8111h, 00:11:22:33:44:55, XID 541, IRQ 136",
                                  "kernel: usb 2-1: Product: USB 10/100/1000 LAN rtl8153",
                                  "kernel: brcm-pcie fd500000.pcie: link up, 5.0 GT/s PCIe x1 (SSC)",
                                  "kernel: bnxt_en 0000:3b:00.0 eth0: Broadcom BCM57414 NetXtreme-E 10Gb/25Gb RDMA Ethernet Controller",
                                  "kernel: health: path loaded", "kernel: breath of fresh air",
                                  "kernel: BIOS-e820: [mem 0x00000000b4300000-0x00000000b43fffff] usable",
                                  "kernel: RIP: 0010:foo+0xb43/0x1f0",
                                  "kernel: ACPI: SSDT 0x00000000DB43A000 0004A4 (v02 INTEL)",
                                  "kernel: BIOS-e820: [mem 0x0000000080211000-0x00000000802fffff] reserved",
                                  "kernel: RAX: ffff8e80211c4000 RBX: 0000000000000000",
                                  "kernel: BIOS-e820: [mem 0x00000000fec80211-0x00000000fec8ffff] reserved"])
def test_unrelated_words_do_not_match(line):
    assert not adapters.WIFI_LOG_PATTERN.search(line.lower())
