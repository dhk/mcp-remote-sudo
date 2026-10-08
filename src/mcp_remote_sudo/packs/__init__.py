"""Task Packs: the unit of capability that mcp-remote-sudo ships.

A pack declares typed operations. Installing a pack makes its operations
*available*; only the active TaskAuthority makes them *exposed* and callable.
External packs register a ``TaskPack`` (or a zero-argument callable returning
one) under the ``mcp_remote_sudo.packs`` entry-point group.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import Any, Callable, Iterable

ENTRY_POINT_GROUP = "mcp_remote_sudo.packs"
REQUIRED = object()


class PackError(ValueError):
    pass


@dataclass(frozen=True)
class Param:
    name: str
    type: type
    default: Any = REQUIRED
    # A gated parameter widens what the operation reads when set to a non-default value (e.g. older boots).
    # Non-default values are allowed only if the matching grant rule constrains this argument explicitly, so
    # manifests written before the parameter existed keep their original scope.
    gated: bool = False


@dataclass(frozen=True)
class Operation:
    name: str                      # authority name, e.g. "wifi.scan"
    tool: str                      # MCP tool name, e.g. "wifi_scan"
    adapter: Callable[..., dict]
    params: tuple[Param, ...] = ()
    description: str = ""
    mutating: bool = False
    privileges: tuple[str, ...] = ()   # host privileges the adapter needs, e.g. "journal-read"
    needs_runtime: bool = False        # adapter receives the server Runtime as its first argument

    def gated_in_use(self, args: dict[str, Any]) -> list[str]:
        return [p.name for p in self.params if p.gated and p.name in args and args[p.name] != p.default]

    def normalize(self, supplied: dict[str, Any]) -> dict[str, Any]:
        """Return the full argument mapping (defaults filled in) that is evaluated and receipted."""
        args = {}
        for p in self.params:
            if p.name in supplied:
                args[p.name] = supplied[p.name]
            elif p.default is not REQUIRED:
                args[p.name] = p.default
        return args


@dataclass(frozen=True)
class TaskPack:
    name: str
    version: str
    operations: tuple[Operation, ...]
    description: str = ""
    templates: dict[str, dict] = field(default_factory=dict)


class Registry:
    def __init__(self, packs: Iterable[TaskPack]):
        self.packs: dict[str, TaskPack] = {}
        self.operations: dict[str, Operation] = {}
        tools: dict[str, str] = {}
        for pack in packs:
            if pack.name in self.packs:
                raise PackError(f"duplicate pack: {pack.name}")
            self.packs[pack.name] = pack
            for op in pack.operations:
                if op.name in self.operations:
                    raise PackError(f"operation {op.name} provided by more than one pack")
                if op.tool in tools:
                    raise PackError(f"MCP tool name {op.tool} used by {tools[op.tool]} and {op.name}")
                self.operations[op.name] = op
                tools[op.tool] = op.name

    def pack_of(self, operation: str) -> str:
        return next(p.name for p in self.packs.values() if any(o.name == operation for o in p.operations))

    def require(self, names: Iterable[str]) -> list[Operation]:
        """Operations for the given authority names; fail closed on any name no installed pack provides."""
        names = sorted(set(names))
        missing = [n for n in names if n not in self.operations]
        if missing:
            raise PackError(f"authority allows operations no installed pack provides: {missing}")
        return [self.operations[n] for n in names]


def builtin_packs() -> list[TaskPack]:
    from . import core, wifi
    return [core.PACK, wifi.PACK]


def discover_packs() -> list[TaskPack]:
    found = []
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        obj = ep.load()
        pack = obj() if callable(obj) and not isinstance(obj, TaskPack) else obj
        if not isinstance(pack, TaskPack):
            raise PackError(f"entry point {ep.name} did not provide a TaskPack")
        runtime_ops = [op.name for op in pack.operations if op.needs_runtime]
        if runtime_ops:
            # needs_runtime hands the adapter the whole Runtime (authority, writable receipts, every manifest's
            # receipts): built-in operations only.
            raise PackError(f"external pack {pack.name} may not declare needs_runtime operations: {runtime_ops}")
        found.append(pack)
    return found


def default_registry() -> Registry:
    return Registry([*builtin_packs(), *discover_packs()])
