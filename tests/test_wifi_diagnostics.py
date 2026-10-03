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


def test_kernel_wifi_log_is_bounded_and_filtered(monkeypatch):
    output="unrelated kernel line\nwl: scan status failed\nNetworkManager: device changed\n"
    def fake_run(argv,timeout=15):
        assert list(argv)==["journalctl","-k","-b","-n","100","--no-pager","-o","short-iso"]
        return {"argv":list(argv),"returncode":0,"stdout":output,"stderr":""}
    monkeypatch.setattr(adapters,"run",fake_run)
    result=adapters.kernel_wifi_log(100)["journalctl"]["stdout"]
    assert "wl: scan status failed" in result
    assert "NetworkManager: device changed" in result
    assert "unrelated kernel line" not in result
    with pytest.raises(ValueError):
        adapters.kernel_wifi_log(501)
    with pytest.raises(ValueError):
        adapters.kernel_wifi_log(True)
