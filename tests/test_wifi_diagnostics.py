import pytest
from mcp_remote_sudo import adapters


def test_wifi_driver_status_validates_module(monkeypatch):
    calls=[]
    monkeypatch.setattr(adapters,"run",lambda argv,timeout=15: calls.append((list(argv),timeout)) or {"argv":list(argv),"returncode":0,"stdout":"","stderr":""})
    monkeypatch.setattr(adapters.Path,"is_dir",lambda self: True)
    result=adapters.wifi_driver_status("wl")
    assert result["loaded"] is True
    assert [c[0] for c in calls] == [["uname","-r"],["modinfo","--","wl"]]
    for bad in ("wl;reboot","--help","-wl"):
        with pytest.raises(ValueError):
            adapters.wifi_driver_status(bad)


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
    def fake_run(argv,timeout=15):
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
