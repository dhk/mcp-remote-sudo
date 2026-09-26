from __future__ import annotations
import hashlib, json, threading, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

class ReceiptWriter:
    def __init__(self, path: str | Path):
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock(); self._previous_hash = self._last_hash()
    def _last_hash(self):
        if not self.path.exists(): return None
        lines=[x for x in self.path.read_text().splitlines() if x.strip()]
        return json.loads(lines[-1])["receipt_hash"] if lines else None
    def write(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            receipt={"receipt_id":str(uuid.uuid4()),"timestamp":datetime.now(timezone.utc).isoformat(),"previous_receipt_hash":self._previous_hash,**payload}
            canonical=json.dumps(receipt,sort_keys=True,separators=(",",":")).encode()
            receipt["receipt_hash"]=hashlib.sha256(canonical).hexdigest()
            with self.path.open("a",encoding="utf-8") as fh: fh.write(json.dumps(receipt,sort_keys=True)+"\n")
            self._previous_hash=receipt["receipt_hash"]; return receipt
