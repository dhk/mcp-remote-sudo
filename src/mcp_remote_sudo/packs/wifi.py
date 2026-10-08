"""Built-in ``wifi`` pack: bounded Wi-Fi and connectivity diagnostics."""
from typing import Optional

from .. import adapters
from . import Operation, Param, TaskPack

PACK = TaskPack(
    name="wifi",
    version="1",
    description="Read-only Wi-Fi, driver and connectivity diagnostics.",
    operations=(
        Operation("wifi.status", "wifi_status", adapters.wifi_status,
                  description="NetworkManager device status."),
        Operation("wifi.scan", "wifi_scan", adapters.wifi_scan,
                  description="Visible Wi-Fi networks."),
        Operation("wifi.driver.status", "wifi_driver_status", adapters.wifi_driver_status,
                  (Param("module", str),),
                  description="Running kernel, loaded state and modinfo for an allowlisted module."),
        Operation("kernel.wifi.log", "kernel_wifi_log", adapters.kernel_wifi_log,
                  (Param("lines", int, 100), Param("boot", int, 0, gated=True),
                   Param("since_minutes", Optional[int], None), Param("include_firewall", bool, False, gated=True)),
                  description="Kernel log filtered to Wi-Fi/driver terms (firewall drops excluded by default); "
                              "boot 0 current, -1 previous; returns at most `lines` matches.",
                  privileges=("journal-read",)),
        Operation("network.probe", "connectivity_probe", adapters.connectivity_probe,
                  (Param("target", str), Param("count", int, 4)),
                  description="Bounded ICMP probe to an allowlisted target.",
                  privileges=("icmp",)),
    ),
)
