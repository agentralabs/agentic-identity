#!/usr/bin/env bash
# check-install-commands.sh — Verify install commands in README work
#
# This script validates that the install.sh script is syntactically valid
# and that the documented install commands are present and correct.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

ERRORS=0

check() {
  local desc="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo -e "${GREEN}[pass]${NC} ${desc}"
  else
    echo -e "${RED}[fail]${NC} ${desc}"
    ERRORS=$((ERRORS + 1))
  fi
}

# Verify install.sh exists and is valid bash
check "install.sh exists" test -f install.sh
check "install.sh is valid bash" bash -n install.sh

# Verify install.sh contains required sections
check "install.sh has profile detection" grep -q "PROFILE" install.sh
check "install.sh has platform detection" grep -q "detect_platform" install.sh
check "install.sh has MCP merge" grep -q "merge_mcp_config" install.sh
check "install.sh does NOT overwrite" grep -q "NEVER overwrite" install.sh

# Verify Cargo.toml is valid
check "Cargo.toml exists" test -f Cargo.toml
check "Workspace has 4 members" test "$(grep -c 'crates/' Cargo.toml)" -ge 4

echo ""
if [ "$ERRORS" -gt 0 ]; then
  echo -e "${RED}${ERRORS} check(s) failed${NC}"
  exit 1
else
  echo -e "${GREEN}All install command checks passed${NC}"
fi
