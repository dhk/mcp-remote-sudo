"""Built-in ``wifi`` pack: bounded Wi-Fi and connectivity diagnostics."""
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
                  (Param("lines", int, 100),),
                  description="Current-boot kernel log filtered to Wi-Fi/driver terms.",
                  privileges=("journal-read",)),
        Operation("network.probe", "connectivity_probe", adapters.connectivity_probe,
                  (Param("target", str), Param("count", int, 4)),
                  description="Bounded ICMP probe to an allowlisted target.",
                  privileges=("icmp",)),
    ),
)
