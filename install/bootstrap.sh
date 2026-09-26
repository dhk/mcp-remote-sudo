#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${MCP_REMOTE_SUDO_REPO:-https://github.com/dhk/mcp-remote-sudo.git}"
REF="${MCP_REMOTE_SUDO_REF:-main}"
TMP="$(mktemp -d)"
cleanup(){ rm -rf "$TMP"; }
trap cleanup EXIT

command -v git >/dev/null 2>&1 || {
  echo "mcp-remote-sudo bootstrap requires git" >&2
  exit 2
}

echo "mcp-remote-sudo bootstrap"
echo "source: $REPO_URL"
echo "ref: $REF"

git clone --quiet --filter=blob:none "$REPO_URL" "$TMP/repo"
git -C "$TMP/repo" checkout --quiet "$REF"

RESOLVED="$(git -C "$TMP/repo" rev-parse HEAD)"
echo "resolved_commit: $RESOLVED"

exec bash "$TMP/repo/install/install.sh"
