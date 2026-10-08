import json
from mcp_remote_sudo.receipts import ReceiptWriter
def test_receipts_form_hash_chain(tmp_path):
    path=tmp_path/"receipts.jsonl"; w=ReceiptWriter(path)
    first=w.write({"tool":"network.status","result":"success"}); second=w.write({"tool":"wifi.scan","result":"denied"})
    assert second["previous_receipt_hash"]==first["receipt_hash"]
    rows=[json.loads(x) for x in path.read_text().splitlines()]; assert len(rows)==2


import asyncio
import pytest
from mcp_remote_sudo.authority import Authority
from mcp_remote_sudo.receipts import verify_chain
from mcp_remote_sudo.server import Runtime, build_server


def chain(tmp_path, n=4):
    path=tmp_path/"r.jsonl"; w=ReceiptWriter(path)
    for i in range(n): w.write({"tool":f"t{i}","manifest_hash":"m1" if i%2==0 else "m2","result":"success"})
    return path


def rewrite(path, rows): path.write_text("".join(json.dumps(r,sort_keys=True)+"\n" for r in rows))


def test_verify_chain_accepts_intact_chain(tmp_path):
    path=chain(tmp_path); result=verify_chain(path)
    assert result["ok"] and result["count"]==4 and result["head"]==json.loads(path.read_text().splitlines()[-1])["receipt_hash"]


def test_verify_chain_detects_modification(tmp_path):
    path=chain(tmp_path); rows=[json.loads(x) for x in path.read_text().splitlines()]
    rows[1]["result"]="denied"; rewrite(path,rows)
    assert verify_chain(path)=={"ok":False,"count":1,"line":2,"reason":"hash_mismatch"}


@pytest.mark.parametrize("mutate,line", [(lambda r: [r[1],r[0],*r[2:]],1), (lambda r: [r[0],*r[2:]],2)])
def test_verify_chain_detects_reordering_and_deletion(tmp_path, mutate, line):
    path=chain(tmp_path); rows=[json.loads(x) for x in path.read_text().splitlines()]
    rewrite(path,mutate(rows))
    result=verify_chain(path); assert not result["ok"] and result["reason"]=="broken_link" and result["line"]==line


def test_verify_chain_rejects_garbage(tmp_path):
    path=chain(tmp_path); path.write_text(path.read_text()+"not json\n")
    assert verify_chain(path)["reason"]=="invalid_json"


def test_tail_filters_by_manifest_hash_and_bounds(tmp_path):
    w=ReceiptWriter(chain(tmp_path,6))
    assert [r["tool"] for r in w.tail(2,manifest_hash="m1")]==["t2","t4"]
    assert w.tail(5,manifest_hash="nope")==[]


def test_receipts_tail_tool_end_to_end(tmp_path):
    a=Authority({"apiVersion":"mcp-remote-sudo/v1","kind":"TaskAuthority","metadata":{"id":"r"},
                 "binding":{"agent":"a","session":"s","host":"h"},
                 "lifetime":{"notAfter":"2099-01-01T00:00:00Z","renewable":False,"expansion":"prohibited"},
                 "allow":[{"tool":"receipts.tail","args":{"lines":{"maximum":50}}},{"tool":"system.info"}]})
    w=ReceiptWriter(tmp_path/"r.jsonl"); w.write({"tool":"old","manifest_hash":"other-manifest"})
    rt=Runtime(a,w,agent="a",session="s",host="h")
    server=build_server(rt)
    with pytest.raises(Exception): asyncio.run(server.call_tool("receipts_tail",{"lines":51}))  # denied by manifest
    out=asyncio.run(server.call_tool("receipts_tail",{"lines":10}))
    payload=json.loads(out[0][0].text) if isinstance(out,tuple) else json.loads(out[0].text)
    assert payload["manifest_hash"]==a.manifest_hash
    assert [r["arguments"] for r in payload["receipts"]]==[{"lines":51}]   # only this manifest's (denied) attempt
    assert payload["receipts"][0]["decision"]=="deny"
    assert verify_chain(tmp_path/"r.jsonl")["ok"]


@pytest.mark.parametrize("lines", [0, 201, 10_000])  # (True is coerced to 1 by the MCP schema layer: in bounds)
def test_receipts_tail_adapter_bound_holds_without_a_manifest_maximum(tmp_path, lines):
    a=Authority({"apiVersion":"mcp-remote-sudo/v1","kind":"TaskAuthority","metadata":{"id":"r"},
                 "binding":{"agent":"a","session":"s","host":"h"},
                 "lifetime":{"notAfter":"2099-01-01T00:00:00Z","renewable":False,"expansion":"prohibited"},
                 "allow":[{"tool":"receipts.tail"}]})
    rt=Runtime(a,ReceiptWriter(tmp_path/"r.jsonl"),agent="a",session="s",host="h")
    with pytest.raises(Exception): asyncio.run(build_server(rt).call_tool("receipts_tail",{"lines":lines}))
    assert json.loads((tmp_path/"r.jsonl").read_text().splitlines()[-1])["result"] in ("failed","denied")


def test_suffix_rewrite_is_only_caught_by_an_external_anchor(tmp_path):
    """Documented limitation: an unkeyed chain re-hashed after tampering verifies; the head changes."""
    from mcp_remote_sudo.receipts import receipt_hash
    path=chain(tmp_path); rows=[json.loads(x) for x in path.read_text().splitlines()]
    anchor=verify_chain(path)["head"]
    rows[0]["tool"]="forged"; prev=None
    for r in rows:
        r["previous_receipt_hash"]=prev; r["receipt_hash"]=receipt_hash(r); prev=r["receipt_hash"]
    rewrite(path,rows)
    result=verify_chain(path)
    assert result["ok"] and result["head"]!=anchor
