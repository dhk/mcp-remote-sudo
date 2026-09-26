#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL="$ROOT/install/install.sh"

bash -n "$INSTALL"
bash -n "$ROOT/install/uninstall.sh"

out="$(bash "$INSTALL" --plan || true)"
grep -q '^BOOTSTRAP_PLAN$' <<<"$out"
grep -q 'LISTEN: 127.0.0.1:' <<<"$out"
grep -q 'RUNTIME_PRIVILEGED_MUTATION: disabled' <<<"$out"

# Source-level safety assertions for the bootstrap script.
! grep -Eq '0\.0\.0\.0|NOPASSWD: *ALL|chmod +777|shell=True' "$INSTALL"
grep -q 'NoNewPrivileges=true' "$INSTALL"
grep -q 'ProtectSystem=strict' "$INSTALL"

echo "installer contract tests passed"
