"""Built-in ``core`` pack: host, network and systemd read-only diagnostics."""
from typing import Optional

from .. import adapters
from . import Operation, Param, TaskPack


def authority_propose(runtime, purpose: str, operations: list[str],
                      constraints: Optional[dict[str, dict]] = None, ttl_minutes: int = 120) -> dict:
    """Draft (never grant) an authority for the operator to review and grant by digest."""
    from .. import proposals
    if runtime.state_dir is None:
        raise ValueError("proposals are unavailable: the service has no state directory")
    manifest, warnings = proposals.render(registry=runtime.registry, active=runtime.authority, purpose=purpose,
                                          operations=operations, constraints=constraints, ttl_minutes=ttl_minutes)
    pid, path, digest = proposals.store(runtime.state_dir, manifest)
    from ..authority import Authority
    return {"id": pid, "sha256": digest, "path": str(path), "warnings": warnings,
            "diff": proposals.diff_text(runtime.authority, Authority(manifest)),
            "yaml": path.read_text(),
            "grant_command": f"sudo mcp-remote-sudo-admin grant --proposal {pid} --sha256 {digest}"}


def receipts_tail(runtime, lines: int = 20) -> dict:
    """Receipts recorded under the active authority (this manifest hash only), oldest first."""
    if not isinstance(lines, int) or isinstance(lines, bool) or lines < 1 or lines > 200:
        raise ValueError("lines must be between 1 and 200")
    rows = runtime.receipts.tail(lines, manifest_hash=runtime.authority.manifest_hash)
    return {"manifest_hash": runtime.authority.manifest_hash, "receipts": rows, "returned": len(rows)}

PACK = TaskPack(
    name="core",
    version="1",
    description="Read-only host, network, systemd and journal diagnostics.",
    templates={"read-only": {"description": "Bounded read-only host diagnostics.", "rules": {
        "journal.query": {"lines": {"minimum": 1, "maximum": 200}},
        "journal.boots": {"limit": {"minimum": 1, "maximum": 50}},
        "receipts.tail": {"lines": {"minimum": 1, "maximum": 200}},
    }}},
    operations=(
        Operation("system.info", "system_info", adapters.system_info,
                  description="Kernel and OS release."),
        Operation("network.status", "network_status", adapters.network_status,
                  description="Interfaces, addresses and routes."),
        Operation("systemd.status", "systemd_status", adapters.systemd_status,
                  (Param("unit", str),),
                  description="systemctl show for one unit."),
        Operation("journal.query", "journal_query", adapters.journal_query,
                  (Param("unit", str), Param("lines", int, 100),
                   Param("boot", Optional[int], None), Param("since_minutes", Optional[int], None)),
                  description="Last N journal lines for one unit; optionally one boot (0 current, -1 previous) "
                              "and/or the last N minutes.",
                  privileges=("journal-read",)),
        Operation("journal.boots", "journal_boots", adapters.journal_boots,
                  (Param("limit", int, 20),),
                  description="Most recent boots with first/last journal entry.",
                  privileges=("journal-read",)),
        Operation("authority.propose", "authority_propose", authority_propose,
                  (Param("purpose", str), Param("operations", list[str]),
                   Param("constraints", Optional[dict[str, dict]], None), Param("ttl_minutes", int, 120)),
                  description="Draft an authority for the operator to review and grant by digest. Grants nothing.",
                  needs_runtime=True),
        Operation("receipts.tail", "receipts_tail", receipts_tail,
                  (Param("lines", int, 20),),
                  description="Receipts recorded under the active authority (bounded), oldest first.",
                  needs_runtime=True),
    ),
)
