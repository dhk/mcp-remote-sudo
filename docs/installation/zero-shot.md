# Zero-shot installation and bootstrap contract

Status: proposed  
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

## Uninstall

Uninstall must be explicit and independently callable.

Expected sequence:

1. stop and disable the service;
2. remove the systemd unit;
3. remove installed program files;
4. remove runtime permission grants;
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
