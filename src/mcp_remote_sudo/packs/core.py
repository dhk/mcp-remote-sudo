"""Built-in ``core`` pack: host, network and systemd read-only diagnostics."""
from .. import adapters
from . import Operation, Param, TaskPack

PACK = TaskPack(
    name="core",
    version="1",
    description="Read-only host, network, systemd and journal diagnostics.",
    operations=(
        Operation("system.info", "system_info", adapters.system_info,
                  description="Kernel and OS release."),
        Operation("network.status", "network_status", adapters.network_status,
                  description="Interfaces, addresses and routes."),
        Operation("systemd.status", "systemd_status", adapters.systemd_status,
                  (Param("unit", str),),
                  description="systemctl show for one unit."),
        Operation("journal.query", "journal_query", adapters.journal_query,
                  (Param("unit", str), Param("lines", int, 100)),
                  description="Last N journal lines for one unit.",
                  privileges=("journal-read",)),
    ),
)
