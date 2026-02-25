#!/usr/bin/env bash
# check-canonical-sister.sh — Verify canonical sister requirements
#
# Every Agentra Labs sister project must meet these requirements:
# 1. Has install.sh at repo root
# 2. Has .github/workflows/ci.yml
# 3. Has Cargo.toml workspace
# 4. Has docs/public/ directory
# 5. Has LICENSE file
# 6. Has proper crate naming (agentic-*)
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

# Core files
check "install.sh exists" test -f install.sh
check "CI workflow exists" test -f .github/workflows/ci.yml
check "Release workflow exists" test -f .github/workflows/release.yml
check "Cargo.toml workspace exists" test -f Cargo.toml
check ".gitignore exists" test -f .gitignore

# Directory structure
check "docs/public/ exists" test -d docs/public
check "crates/ directory exists" test -d crates

# Crate naming
check "Core crate is agentic-identity" grep -q 'name = "agentic-identity"' crates/agentic-identity/Cargo.toml
check "CLI crate is agentic-identity-cli" grep -q 'name = "agentic-identity-cli"' crates/agentic-identity-cli/Cargo.toml
check "MCP crate is agentic-identity-mcp" grep -q 'name = "agentic-identity-mcp"' crates/agentic-identity-mcp/Cargo.toml

# Workspace config
check "Workspace has resolver = 2" grep -q 'resolver = "2"' Cargo.toml
check "Repository URL set" grep -q "agentralabs" Cargo.toml

echo ""
if [ "$ERRORS" -gt 0 ]; then
  echo -e "${RED}${ERRORS} check(s) failed${NC}"
  exit 1
else
  echo -e "${GREEN}All canonical sister checks passed${NC}"
fi
