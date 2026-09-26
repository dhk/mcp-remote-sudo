from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    rule: dict[str, Any] | None = None


class Authority:
    TOP_LEVEL = {"apiVersion", "kind", "metadata", "binding", "lifetime", "allow", "deny", "receipts"}

    def __init__(self, manifest: dict[str, Any]):
        self.manifest = manifest
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        self.manifest_hash = hashlib.sha256(canonical).hexdigest()
        self._validate()

    @classmethod
    def load(cls, path: str | Path) -> "Authority":
        data = yaml.safe_load(Path(path).read_text())
        if not isinstance(data, dict):
            raise ManifestError("manifest must be a mapping")
        return cls(data)

    def _validate(self) -> None:
        unknown = set(self.manifest) - self.TOP_LEVEL
        if unknown:
            raise ManifestError(f"unknown top-level fields: {sorted(unknown)}")
        if self.manifest.get("apiVersion") != "mcp-remote-sudo/v1":
            raise ManifestError("unsupported apiVersion")
        if self.manifest.get("kind") != "TaskAuthority":
            raise ManifestError("kind must be TaskAuthority")
        for key in ("metadata", "binding", "lifetime", "allow"):
            if key not in self.manifest:
                raise ManifestError(f"missing required field: {key}")
        if self.manifest["lifetime"].get("renewable") is not False:
            raise ManifestError("v1 manifests must set renewable: false")
        if self.manifest["lifetime"].get("expansion") != "prohibited":
            raise ManifestError("v1 manifests must prohibit expansion")
        if "notAfter" not in self.manifest["lifetime"]:
            raise ManifestError("v1 requires an absolute notAfter timestamp")
        self._parse_time(self.manifest["lifetime"]["notAfter"])
        for collection in ("allow", "deny"):
            for rule in self.manifest.get(collection, []):
                if not isinstance(rule, dict) or not isinstance(rule.get("tool"), str):
                    raise ManifestError(f"{collection} rules require a tool name")
                unknown_rule_fields = set(rule) - {"tool", "args"}
                if unknown_rule_fields:
                    raise ManifestError(
                        f"{collection} rule for {rule['tool']} has unknown fields: {sorted(unknown_rule_fields)}"
                    )
                if "args" in rule and not isinstance(rule["args"], dict):
                    raise ManifestError(f"{collection} rule args must be a mapping")

    @staticmethod
    def _parse_time(value: str) -> datetime:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise ManifestError("invalid notAfter timestamp") from exc
        if dt.tzinfo is None:
            raise ManifestError("notAfter must include timezone")
        return dt

    @property
    def allowed_tools(self) -> set[str]:
        return {rule["tool"] for rule in self.manifest["allow"]}

    def check_binding(self, *, agent: str, session: str, host: str) -> Decision:
        expected = self.manifest["binding"]
        actual = {"agent": agent, "session": session, "host": host}
        for key, value in actual.items():
            if expected.get(key) != value:
                return Decision(False, f"binding_mismatch:{key}")
        return Decision(True, "binding_match")

    def evaluate(self, tool: str, args: dict[str, Any], *, now: datetime | None = None) -> Decision:
        now = now or datetime.now(timezone.utc)
        if now >= self._parse_time(self.manifest["lifetime"]["notAfter"]):
            return Decision(False, "manifest_expired")
        for rule in self.manifest.get("deny", []):
            if rule["tool"] == tool:
                return Decision(False, "explicit_deny", rule)
        candidates = [r for r in self.manifest["allow"] if r["tool"] == tool]
        if not candidates:
            return Decision(False, "tool_not_allowed")
        for rule in candidates:
            if self._args_match(args, rule.get("args", {})):
                return Decision(True, "allowed", rule)
        return Decision(False, "arguments_not_allowed")

    @staticmethod
    def _args_match(args: dict[str, Any], constraints: dict[str, Any]) -> bool:
        for name, spec in constraints.items():
            if name not in args:
                return False
            value = args[name]
            if not isinstance(spec, dict):
                if value != spec:
                    return False
                continue
            unknown = set(spec) - {"enum", "minimum", "maximum"}
            if unknown:
                return False
            if "enum" in spec and value not in spec["enum"]:
                return False
            if "minimum" in spec and (not isinstance(value, (int, float)) or value < spec["minimum"]):
                return False
            if "maximum" in spec and (not isinstance(value, (int, float)) or value > spec["maximum"]):
                return False
        return True
