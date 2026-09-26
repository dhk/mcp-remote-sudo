# Self-update Task Pack

## Purpose

The self-update Task Pack lets an authorized MCP client update mcp-remote-sudo without granting the MCP runtime general administrative authority.

This is a Task Pack, not a generic package-management or shell capability.

## Trust boundary

The unprivileged mcp-remote-sudo service requests an update. A separately installed, root-owned helper performs the privileged transition. The helper has one purpose: replace mcp-remote-sudo with an approved version from its canonical source and recover the previous healthy version if activation fails.

```text
MCP client
    |
    v
mcp-remote-sudo (unprivileged)
    |
    | bounded update request
    v
root-owned update helper
    |
    +-- verify approved source and artifact
    +-- stage replacement
    +-- atomically activate
    +-- restart mcp-remote-sudo.service
    +-- verify sustained health
    +-- rollback on failure
    +-- emit receipt
```

## Allowed authority

The helper may:

- discover an update from the configured canonical mcp-remote-sudo source;
- verify the selected release/ref according to the configured integrity policy;
- write only the mcp-remote-sudo installation/staging locations it owns;
- restart only `mcp-remote-sudo.service`;
- run the product-specific health verification;
- restore the immediately previous known-good installation when verification fails.

## Explicit non-authority

The Task Pack does not grant:

- arbitrary shell execution;
- arbitrary Git repositories or URLs;
- general package installation;
- arbitrary filesystem writes;
- arbitrary systemd service control;
- modification of unrelated sudoers or policy configuration;
- persistent root authority to the MCP runtime.

## MCP operation

The intended interface is a typed operation such as:

```text
mcp_remote_sudo.update(version=<approved-version-or-policy>)
```

The exact schema should make source selection non-arbitrary. A default operation may mean "latest approved release" rather than accepting a caller-supplied URL.

## Transaction

1. Resolve the requested version under policy.
2. Verify provenance and integrity.
3. Stage without modifying the active installation.
4. Record the currently active known-good version.
5. Atomically activate the staged version.
6. Restart only mcp-remote-sudo.
7. Apply the same sustained-health verification used by installation.
8. On failure, restore the known-good version and restart.
9. Emit an append-only receipt describing update or rollback.

## Acceptance criteria

Implementation is complete when:

- source and artifact are constrained and verified;
- privileged work occurs in an independently narrow root-owned helper;
- activation is atomic;
- a failed activation automatically rolls back;
- update and rollback are receipted;
- the MCP runtime retains no general root/sudo capability;
- tests demonstrate that malformed arguments cannot escape the update operation.

Implementation is tracked by #16.
