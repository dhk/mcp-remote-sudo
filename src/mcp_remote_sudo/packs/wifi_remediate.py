"""Built-in ``wifi-remediate`` pack (#43): the recovery ladder for a wedged Wi-Fi driver, least invasive first.

Every operation is mutating: it runs in the root helper, which re-checks the grant, requires resource arguments to be
pinned by an enum in that grant, and (by default) consumes a single-use operator approval before acting.
"""
from . import Operation, Param, TaskPack, helper_adapter

PACK = TaskPack(
    name="wifi-remediate",
    version="1",
    description="Wi-Fi recovery: radio toggle, scoped service restart, allowlisted module reload (via the helper).",
    templates={"remediate": {"description": "Recovery ladder for a wedged wl driver (operator confirms each step).", "rules": {
        "wifi.radio.set": {"state": {"enum": ["on", "off"]}},
        "service.restart": {"unit": {"enum": ["wpa_supplicant.service", "NetworkManager.service"]}},
        "kernel.module.reload": {"name": {"enum": ["wl"]}},
    }}},
    operations=(
        Operation("wifi.radio.set", "wifi_radio_set", helper_adapter("wifi.radio.set"), (Param("state", str),),
                  description="Turn the Wi-Fi radio on or off (receipt records the inverse).",
                  mutating=True, privileges=("helper",)),
        Operation("service.restart", "service_restart", helper_adapter("service.restart"), (Param("unit", str),),
                  description="Restart one .service unit the grant enumerates.",
                  mutating=True, privileges=("helper",)),
        Operation("kernel.module.reload", "kernel_module_reload", helper_adapter("kernel.module.reload"),
                  (Param("name", str),),
                  description="Unload and reload one kernel module the grant enumerates (e.g. wl).",
                  mutating=True, privileges=("helper", "CAP_SYS_MODULE")),
    ),
)
