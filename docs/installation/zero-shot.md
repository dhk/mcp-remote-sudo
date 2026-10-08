# Installation guide

The README gives the shortest path. This page explains the installation choices, their trust trade-offs, and the underlying bootstrap contract.

## Choose an installation path

### 1. One-shot bootstrap — default

```bash
curl -fsSL https://raw.githubusercontent.com/dhk/mcp-remote-sudo/main/install/bootstrap.sh | sudo bash
```

This is the easiest way to get started. The small bootstrap script clones the repository and hands control to the canonical installer; it does not contain a second copy of the installation logic.

**Trade-off:** this executes the current `main` bootstrap as root. It is convenient, but you are trusting the repository state returned at execution time. Use one of the following paths if that trust model is too broad.

You can select a particular ref:

```bash
curl -fsSL https://raw.githubusercontent.com/dhk/mcp-remote-sudo/main/install/bootstrap.sh -o /tmp/mcp-remote-sudo-bootstrap.sh
sudo env MCP_REMOTE_SUDO_REF=<tag-or-commit> bash /tmp/mcp-remote-sudo-bootstrap.sh
```

### 2. Download, inspect, then run — conservative

```bash
curl -fsSL https://raw.githubusercontent.com/dhk/mcp-remote-sudo/main/install/bootstrap.sh -o mcp-remote-sudo-bootstrap.sh
less mcp-remote-sudo-bootstrap.sh
sudo bash mcp-remote-sudo-bootstrap.sh
```

This removes the blind-pipe step. You can see the bootstrap before granting it root authority, but `main` is still mutable unless you also pin the source.

### 3. Clone and pin — reproducible and auditable

```bash
git clone https://github.com/dhk/mcp-remote-sudo.git
cd mcp-remote-sudo
git checkout <release-tag-or-commit>
git rev-parse HEAD
bash install/install.sh --preflight
bash install/install.sh --plan
sudo bash install/install.sh
```

This is the preferred path when you need to know exactly which source revision received bootstrap authority. It also exposes preflight and the complete bootstrap plan before root execution.

For a security-sensitive deployment, this is the strongest currently supported installation path.

### 4. Packaged install — planned

A published package should eventually remove the Git clone/bootstrap mechanics. For this Python project, `pipx` is the likely user-facing package mechanism because it isolates the application environment.

This path is **not available yet**. Do not use an unrelated package with the same name from a package index.

Packaging does not remove the need for privileged host bootstrap: creating the service account, protected directories, and systemd unit still requires explicit host authorization.

## What the installer changes

Regardless of entry path, installation converges on the same canonical installer and security model described below.

Tracking: #6

## Objective

A competent automation agent arriving at an unfamiliar supported Linux host should need only:

1. the `mcp-remote-sudo` repository URL;
2. ordinary user access to the host; and
3. a human willing to authorize clearly identified bootstrap operations that genuinely require elevation.

From that starting point, the agent must be able to determine compatibility, install the software, configure the safe read-only baseline, verify the installation, and produce an unambiguous machine-readable result.

**Zero-shot does not mean zero authorization.** It means the installer does not depend on undocumented machine knowledge, remembered setup steps, or interactive improvisation.

## Security boundary

Installation has two different authorities.

### Bootstrap authority

Bootstrap may need temporary root authority to:

- create the dedicated service account;
- create protected configuration and receipt directories;
- install a systemd unit;
- grant narrowly required journal access;
- enable/start the service.

These operations must be explicit and reviewable. An agent must never interpret installation permission as standing permission to run arbitrary privileged commands.

### Runtime authority

After installation, the service runs as the dedicated `mcp-remote-sudo` account. The initial installation provides read-only diagnostic tools only.

The runtime service must not retain:

- general sudo;
- a root shell;
- arbitrary command execution;
- package-management authority;
- arbitrary filesystem writes;
- reboot/shutdown authority.

Bootstrap authority is therefore **not inherited by runtime authority**.

## Supported-host assumptions for v1

The first installer targets a deliberately narrow platform:

- Linux
- systemd
- Python 3.11 or later
- `ip`
- `systemctl`
- `journalctl`
- NetworkManager/`nmcli` for Wi-Fi-specific tools

A host without NetworkManager may still support non-Wi-Fi tools, but v1 should report that capability as unavailable rather than silently substituting another network stack.

The installer must detect assumptions. It must not install missing operating-system packages automatically unless a future installation mode explicitly authorizes package management.

## Canonical layout

```text
/etc/mcp-remote-sudo/
    authority.yaml

/var/lib/mcp-remote-sudo/
    # reserved durable service state

/var/log/mcp-remote-sudo/
    receipts.jsonl

/etc/systemd/system/
    mcp-remote-sudo.service
```

The Python package may live in a dedicated virtual environment such as:

```text
/opt/mcp-remote-sudo/venv/
```

The service account owns only the state it needs. Configuration and service definitions should remain root-owned. Receipt storage must not be writable by the MCP client/agent identity.

## Installation sequence

### 1. Pin the source

The normative installation path uses an explicit release, tag, or commit.

Example development flow:

```bash
git clone https://github.com/dhk/mcp-remote-sudo.git
cd mcp-remote-sudo
git checkout <EXPECTED_TAG_OR_COMMIT>
git rev-parse HEAD
```

For releases, publish integrity information and verify it before privileged bootstrap.

Blind execution of a mutable network script such as `curl ... | sudo sh` is not the recommended path for this security-sensitive service.

### 2. Preflight without elevation

The installer first reports:

- distribution and kernel
- init system
- Python version
- presence/version of required commands
- NetworkManager availability
- whether the requested port is free
- current hostname
- current user's privilege mechanism
- whether the existing installation/layout is present

Preflight returns one of:

```text
compatible
compatible_with_reduced_capabilities
incompatible
needs_human_bootstrap_authorization
```

Missing requirements are reported individually. Preflight must not mutate the host.

### 3. Show the bootstrap plan

Before requesting elevation, print the exact classes of changes that will occur:

```text
CREATE service user: mcp-remote-sudo
CREATE /etc/mcp-remote-sudo
CREATE /var/lib/mcp-remote-sudo
CREATE /var/log/mcp-remote-sudo
INSTALL Python environment under /opt/mcp-remote-sudo
INSTALL systemd unit mcp-remote-sudo.service
GRANT read access required for configured journal tools
ENABLE and START mcp-remote-sudo.service
LISTEN 127.0.0.1:8765 only
```

If the plan changes after authorization, stop and present the new plan.

### 4. Perform bootstrap

Create the dedicated system account with no interactive login.

Install the pinned software and configuration. The baseline manifest contains only read-only diagnostic capabilities.

Install a hardened systemd service. At minimum evaluate:

- `NoNewPrivileges=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- `PrivateTmp=true`
- explicit writable paths
- restrictive capability bounding
- no ambient capabilities

The service binds only:

```text
127.0.0.1:8765
```

Remote connectivity is provided separately, initially through an SSH local port forward.

### 5. Start and inspect

After starting the service, verify:

- systemd reports active;
- the process identity is the dedicated account;
- the listener is loopback-only;
- the active manifest is the expected manifest;
- no unexpected sudo/capability grants exist;
- the receipt path is writable by the service and protected from the agent/client identity.

A running process is not sufficient evidence of a successful installation.

## Verification protocol

The installer must execute behavioral verification.

### Positive test

Invoke one operation explicitly allowed by the baseline manifest, such as `system.info`.

Expected:

```text
authorization: allow
execution: success
receipt: present
```

### Constraint test

Invoke an allowed parameterized tool outside its argument envelope—for example a journal request exceeding the configured maximum.

Expected:

```text
authorization: deny
execution: not attempted
receipt: present
reason: arguments_not_allowed
```

### Prohibited-operation test

Attempt a tool absent from the authority manifest.

Expected:

```text
authorization: deny
execution: not attempted
receipt: present
```

### Receipt verification

Verify that:

- each test generated a receipt;
- receipts contain the expected manifest hash and binding;
- the hash chain is internally consistent;
- denied operations did not reach an adapter.

Installation is not `ready` until these checks pass.

## Machine-readable completion contract

Successful installation prints a stable block:

```text
MCP_REMOTE_SUDO_INSTALL
schema: 1
status: ready
version: <installed-version>
source_commit: <sha>
endpoint: http://127.0.0.1:8765/mcp
service: mcp-remote-sudo.service
service_user: mcp-remote-sudo
manifest: /etc/mcp-remote-sudo/authority.yaml
manifest_hash: <sha256>
manifest_backup: <path-or-none>
port_source: env|existing_unit|default
icmp_probe: enabled|already_permitted|disabled|skipped_conflicting_range
receipts: /var/log/mcp-remote-sudo/receipts.jsonl
transport: loopback-only
privileged_mutation: disabled
verification: passed
```

Failure uses the same header/schema and reports `status: failed` or `status: needs_authorization`, plus stable reason codes.

Human-friendly prose may surround the block, but automation must not need to parse that prose.

## Client connection

On the machine running the MCP client:

```bash
ssh -N -L 8765:127.0.0.1:8765 <user>@<host>
```

The local MCP endpoint is then:

```text
http://127.0.0.1:8765/mcp
```

For Claude Code, for example:

```bash
claude mcp add --transport http --scope user mcp-remote-sudo http://127.0.0.1:8765/mcp
```

The SSH login identity and the `mcp-remote-sudo` service identity are deliberately separate.

## Idempotency

Running the installer again against the same version/configuration must be safe.

It should classify each operation as:

```text
create
update
unchanged
conflict
```

Existing configuration must never be overwritten merely because the installer recognizes the path. Security-sensitive conflicts stop installation and require explicit resolution.

## Upgrades

Upgrade is a separate operation from install.

An upgrade must:

1. identify current and target versions;
2. validate the target before mutation;
3. display configuration/schema changes;
4. preserve or explicitly migrate the authority manifest;
5. stop if the target would broaden runtime authority;
6. restart;
7. repeat the complete verification protocol.

A version upgrade must not silently upgrade an authority manifest to broader permissions.

### Reinstalling over an existing installation

Rerunning the installer on a host that already has mcp-remote-sudo is supported and conservative:

- **Port.** The listen port is chosen in this order: `MCP_REMOTE_SUDO_PORT` if set; otherwise the `--port` already in the
  installed unit's `ExecStart`; otherwise `8765`. A reinstall therefore never silently moves the service to another port.
  The completion block reports `port_source: env | existing_unit | default`.
- **Port collisions.** A listener on the chosen port is accepted only if every listening process belongs to
  `mcp-remote-sudo.service` (checked through its cgroup). Another daemon on the same port is a collision (`port_in_use`)
  even while mcp-remote-sudo is running. Unprivileged `--preflight` cannot see other users' sockets and reports
  `port_owner: unverified`; the privileged install repeats the check with full visibility.
- **Authority.** An existing `/etc/mcp-remote-sudo/authority.yaml` is copied to `authority.yaml.bak-<UTC timestamp>`
  before the baseline is written; the completion block reports `manifest_backup:`. Receipts are never modified.

## ICMP probes under systemd hardening

`network.probe` runs `ping`. On most distributions `ping` gets raw-socket access from a file capability
(`cap_net_raw`), which the service cannot gain because its unit sets `NoNewPrivileges=true`. Rather than weaken that,
the installer permits unprivileged ICMP *echo datagram* sockets for the service's group only:

```text
/etc/sysctl.d/60-mcp-remote-sudo-ping.conf
net.ipv4.ping_group_range = <mcp-remote-sudo gid> <mcp-remote-sudo gid>
```

Trade-offs and safeguards:

- This is a host-wide sysctl, but it admits only one group, and only for ICMP echo sockets — not raw sockets.
  The service never receives `CAP_NET_RAW` or any ambient capability.
- The installer only replaces the kernel default (disabled, e.g. `1 0`) or its own previous value. If an administrator
  already configured a range that includes the service group, nothing is written (`icmp_probe: already_permitted`);
  if they configured a range that excludes it, the installer leaves it alone (`icmp_probe: skipped_conflicting_range`)
  and `network.probe` will fail until an administrator decides.
- Opt out with `MCP_REMOTE_SUDO_ICMP=0` (`icmp_probe: disabled`).
- `uninstall.sh` removes the drop-in and, only if the live value is still exactly the service group's range, resets it
  and re-applies the remaining sysctl configuration.

## Uninstall

Uninstall must be explicit and independently callable.

Expected sequence:

1. stop and disable the service;
2. remove the systemd unit;
3. remove installed program files;
4. remove runtime permission grants (including the ICMP sysctl drop-in);
5. optionally remove the service account;
6. preserve receipts by default;
7. preserve authority configuration by default unless explicitly purged;
8. report retained paths.

A `--purge`-style mode may remove retained configuration/receipts, but must name those destructive operations before performing them.

## Troubleshooting rule

Installation failure is not permission to broaden privileges.

The troubleshooting sequence is:

```text
observe
  → identify the failed invariant
  → identify the minimum missing authority/dependency
  → present it
  → obtain explicit bootstrap authorization if required
  → change only that boundary
  → rerun verification
```

Do not fix failures by:

- running the service as root;
- adding unrestricted sudo;
- disabling systemd hardening wholesale;
- binding to `0.0.0.0`;
- making receipt/configuration directories world-writable;
- installing arbitrary packages without explicit authorization.

## Zero-shot acceptance test

A clean-host test should eventually prove the contract:

```text
fresh supported Linux host
        ↓
checkout pinned source
        ↓
preflight
        ↓
reviewed bootstrap
        ↓
installation
        ↓
service healthy
        ↓
allowed MCP call succeeds
        ↓
out-of-policy call denied
        ↓
both leave receipts
        ↓
uninstall
        ↓
service + runtime authority absent
```

CI should run this path in a clean supported Linux environment. Host-specific privileged enforcement tests may require a VM rather than a container.

## Definition of done

Zero-shot installation is complete when an agent with no prior knowledge of the target host can follow this document mechanically and either:

- produce a verified, least-privilege installation; or
- stop with a precise machine-readable explanation of the missing prerequisite or human authorization.

There should be no undocumented third state.

## Forced Wi-Fi rescans (opt-in)

`wifi.scan(rescan=true)` asks NetworkManager for a fresh scan. On Ubuntu, the
`org.freedesktop.NetworkManager.wifi.scan` polkit action is `auth_admin` for callers without a session, so the
unprivileged service is refused by default. Reinstall with `MCP_REMOTE_SUDO_WIFI_RESCAN=1` to install
`/etc/polkit-1/rules.d/60-mcp-remote-sudo-wifi-scan.rules`. That rule grants exactly that one action, to exactly the
`mcp-remote-sudo` user. Setting `MCP_REMOTE_SUDO_WIFI_RESCAN=0` removes the rule, and leaving it unset keeps the current
state. The installer reports `wifi_rescan: enabled|disabled|unchanged|unavailable` (`unavailable`: polkit is not installed, so nothing was written). An invalid value fails before anything is changed.

Even with the rule, a forced rescan needs a grant whose `wifi.scan` rule constrains `rescan`, because `rescan` is a gated
argument. A forced scan can briefly disturb a marginal link.

