from __future__ import annotations
import hashlib, json, threading, uuid
from collections import deque
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

    def tail(self, lines: int, *, manifest_hash: str) -> list[dict[str, Any]]:
        """The last `lines` receipts recorded under one manifest hash (oldest first)."""
        keep: deque[dict[str, Any]] = deque(maxlen=lines)
        if self.path.exists():
            with self.path.open(encoding="utf-8") as fh:
                for raw in fh:
                    if raw.strip():
                        try: row = json.loads(raw)
                        except json.JSONDecodeError: continue
                        if row.get("manifest_hash") == manifest_hash: keep.append(row)
        return list(keep)


def receipt_hash(receipt: dict[str, Any]) -> str:
    body = {k: v for k, v in receipt.items() if k != "receipt_hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_chain(path: str | Path) -> dict[str, Any]:
    """Recompute every receipt hash and link. Detects modification, insertion, deletion and reordering;
    truncation of the newest receipts is only detectable against an externally recorded head hash."""
    previous = None; count = 0
    with Path(path).open(encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            if not raw.strip(): continue
            try: row = json.loads(raw)
            except json.JSONDecodeError: return {"ok": False, "count": count, "line": lineno, "reason": "invalid_json"}
            if not isinstance(row, dict) or "receipt_hash" not in row:
                return {"ok": False, "count": count, "line": lineno, "reason": "missing_hash"}
            if row.get("previous_receipt_hash") != previous:
                return {"ok": False, "count": count, "line": lineno, "reason": "broken_link"}
            if receipt_hash(row) != row["receipt_hash"]:
                return {"ok": False, "count": count, "line": lineno, "reason": "hash_mismatch"}
            previous = row["receipt_hash"]; count += 1
    return {"ok": True, "count": count, "head": previous}
