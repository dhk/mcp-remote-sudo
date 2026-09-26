import json
from mcp_remote_sudo.receipts import ReceiptWriter
def test_receipts_form_hash_chain(tmp_path):
    path=tmp_path/"receipts.jsonl"; w=ReceiptWriter(path)
    first=w.write({"tool":"network.status","result":"success"}); second=w.write({"tool":"wifi.scan","result":"denied"})
    assert second["previous_receipt_hash"]==first["receipt_hash"]
    rows=[json.loads(x) for x in path.read_text().splitlines()]; assert len(rows)==2
