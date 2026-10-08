from __future__ import annotations

import hashlib
import json
import math
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
    # Closed key sets for nested sections: {field: (required, allowed types)}.
    SECTIONS = {
        "metadata": {"id": (True, (str,)), "version": (False, (int,)), "purpose": (False, (str,))},
        "binding": {"agent": (True, (str,)), "session": (True, (str,)), "host": (True, (str,))},
        "lifetime": {"notAfter": (True, (str,)), "renewable": (True, (bool,)), "expansion": (True, (str,))},
        "receipts": {"required": (True, (bool,))},
    }
    CONSTRAINT_KEYS = {"enum", "minimum", "maximum"}

    def __init__(self, manifest: dict[str, Any]):
        self.manifest = manifest
        # Validate before hashing: canonical JSON cannot sort malformed (mixed-type) keys.
        self._validate()
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        self.manifest_hash = hashlib.sha256(canonical).hexdigest()

    @classmethod
    def load(cls, path: str | Path) -> "Authority":
        data = yaml.safe_load(Path(path).read_text())
        if not isinstance(data, dict):
            raise ManifestError("manifest must be a mapping")
        return cls(data)

    def _validate(self) -> None:
        unknown = set(self.manifest) - self.TOP_LEVEL
        if unknown:
            raise ManifestError(f"unknown top-level fields: {sorted(unknown, key=repr)}")
        if self.manifest.get("apiVersion") != "mcp-remote-sudo/v1":
            raise ManifestError("unsupported apiVersion")
        if self.manifest.get("kind") != "TaskAuthority":
            raise ManifestError("kind must be TaskAuthority")
        for key in ("metadata", "binding", "lifetime", "allow"):
            if key not in self.manifest:
                raise ManifestError(f"missing required field: {key}")
        for section, fields in self.SECTIONS.items():
            if section in self.manifest:
                self._validate_section(section, self.manifest[section], fields)
        for collection in ("allow", "deny"):
            if not isinstance(self.manifest.get(collection, []), list):
                raise ManifestError(f"{collection} must be a list")
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
                for name, spec in rule.get("args", {}).items():
                    self._validate_constraint(f"{collection} rule for {rule['tool']} arg {name}", spec)

    @staticmethod
    def _validate_section(section: str, value: Any, fields: dict[str, tuple[bool, tuple[type, ...]]]) -> None:
        if not isinstance(value, dict):
            raise ManifestError(f"{section} must be a mapping")
        unknown = set(value) - set(fields)
        if unknown:
            raise ManifestError(f"{section} has unknown fields: {sorted(unknown, key=repr)}")
        for name, (required, types) in fields.items():
            if name not in value:
                if required:
                    raise ManifestError(f"missing required field: {section}.{name}")
                continue
            # bool is a subclass of int; never accept it where an int is meant.
            if not isinstance(value[name], types) or (bool not in types and isinstance(value[name], bool)):
                raise ManifestError(f"{section}.{name} has invalid type")

    @classmethod
    def _validate_constraint(cls, where: str, spec: Any) -> None:
        if not isinstance(spec, dict):
            if not isinstance(spec, (str, int, float, bool)):
                raise ManifestError(f"{where}: exact-value constraint must be a scalar")
            return
        if not spec:
            raise ManifestError(f"{where}: empty constraint")
        unknown = set(spec) - cls.CONSTRAINT_KEYS
        if unknown:
            raise ManifestError(f"{where}: unknown constraint keys: {sorted(unknown, key=repr)}")
        if "enum" in spec and (not isinstance(spec["enum"], list) or not spec["enum"]):
            raise ManifestError(f"{where}: enum must be a non-empty list")
        for bound in ("minimum", "maximum"):
            if bound in spec and not _is_number(spec[bound]):
                raise ManifestError(f"{where}: {bound} must be a finite number")
        if "minimum" in spec and "maximum" in spec and spec["minimum"] > spec["maximum"]:
            raise ManifestError(f"{where}: minimum exceeds maximum")

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
                if not _same(value, spec):
                    return False
                continue
            unknown = set(spec) - {"enum", "minimum", "maximum"}
            if unknown:
                return False
            if "enum" in spec and not any(_same(value, allowed) for allowed in spec["enum"]):
                return False
            if "minimum" in spec and (not _is_number(value) or value < spec["minimum"]):
                return False
            if "maximum" in spec and (not _is_number(value) or value > spec["maximum"]):
                return False
        return True


def _is_number(value: Any) -> bool:
    """A finite int/float that is not a bool (bool is an int subclass, and NaN defeats comparisons)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _same(value: Any, expected: Any) -> bool:
    """Equality that never treats booleans as numbers (Python considers True == 1)."""
    if isinstance(value, bool) or isinstance(expected, bool):
        return isinstance(value, bool) and isinstance(expected, bool) and value is expected
    return value == expected
