import asyncio
from datetime import datetime, timezone

import pytest

from mcp_remote_sudo import adapters
from mcp_remote_sudo.authority import Authority
from mcp_remote_sudo.server import build_server


@pytest.fixture
def calls(monkeypatch):
    seen=[]
    monkeypatch.setattr(adapters,"run",lambda argv,timeout=15: seen.append(list(argv)) or {"argv":list(argv),"returncode":0,"stdout":"","stderr":""})
    return seen


def test_journal_query_defaults_are_unchanged(calls):
    adapters.journal_query("NetworkManager.service")
    assert calls==[["journalctl","-u","NetworkManager.service","-n","100","--no-pager","-o","short-iso"]]


def test_journal_query_boot_and_since(calls, monkeypatch):
    class FixedDT(datetime):
        @classmethod
        def now(cls,tz=None): return datetime(2026,10,3,12,0,0,tzinfo=timezone.utc)
    monkeypatch.setattr(adapters,"datetime",FixedDT)
    adapters.journal_query("wpa_supplicant.service",200,boot=-1,since_minutes=90)
    assert calls==[["journalctl","-u","wpa_supplicant.service","-n","200","-b","-1",
                    "--since","2026-10-03 10:30:00 UTC","--no-pager","-o","short-iso"]]


@pytest.mark.parametrize("kwargs",[{"boot":1},{"boot":-1001},{"boot":True},{"boot":"-1"},
                                   {"since_minutes":0},{"since_minutes":10081},{"since_minutes":True}])
def test_journal_query_rejects_out_of_range_window(calls, kwargs):
    with pytest.raises(ValueError): adapters.journal_query("NetworkManager.service",100,**kwargs)
    assert calls==[]


def test_journal_boots_is_bounded(monkeypatch):
    out="IDX BOOT ID FIRST LAST\n"+"\n".join(f"{-i} id{i} a b" for i in range(30,-1,-1))
    monkeypatch.setattr(adapters,"run",lambda argv,timeout=15: {"argv":list(argv),"returncode":0,"stdout":out,"stderr":""})
    rows=adapters.journal_boots(3)["journalctl"]["stdout"].splitlines()
    assert rows==["IDX BOOT ID FIRST LAST","-2 id2 a b","-1 id1 a b","0 id0 a b"]
    for bad in (0,101,True):
        with pytest.raises(ValueError): adapters.journal_boots(bad)


def test_manifest_bounds_boot_and_window():
    a=Authority({"apiVersion":"mcp-remote-sudo/v1","kind":"TaskAuthority","metadata":{"id":"j"},
                 "binding":{"agent":"a","session":"s","host":"h"},
                 "lifetime":{"notAfter":"2099-01-01T00:00:00Z","renewable":False,"expansion":"prohibited"},
                 "allow":[{"tool":"journal.query","args":{"unit":{"enum":["wpa_supplicant.service"]},
                           "boot":{"minimum":-3,"maximum":0},"since_minutes":{"maximum":1440}}}]})
    ok={"unit":"wpa_supplicant.service","lines":100,"boot":-1,"since_minutes":60}
    assert a.evaluate("journal.query",ok).allowed
    assert not a.evaluate("journal.query",{**ok,"boot":-4}).allowed
    assert not a.evaluate("journal.query",{**ok,"since_minutes":2000}).allowed
    # A constrained argument must be supplied explicitly: the unbounded default (None) is denied.
    assert not a.evaluate("journal.query",{**ok,"boot":None}).allowed


def test_journal_tool_schema_exposes_optional_window():
    class RT:
        authority=Authority({"apiVersion":"mcp-remote-sudo/v1","kind":"TaskAuthority","metadata":{"id":"j"},
            "binding":{"agent":"a","session":"s","host":"h"},
            "lifetime":{"notAfter":"2099-01-01T00:00:00Z","renewable":False,"expansion":"prohibited"},
            "allow":[{"tool":"journal.query"},{"tool":"journal.boots"}]})
        def invoke(self,tool,args,fn): return {}
    tools={t.name:t for t in asyncio.run(build_server(RT()).list_tools())}
    props=tools["journal_query"].inputSchema["properties"]
    assert {"boot","since_minutes"}<=set(props) and tools["journal_query"].inputSchema["required"]==["unit"]
    assert "journal_boots" in tools
