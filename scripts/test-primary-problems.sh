#!/usr/bin/env bash
# test-primary-problems.sh — Primary problem regression tests
#
# These tests verify the three core inventions work end-to-end:
# 1. Identity Anchor — create, derive, sign, verify
# 2. Action Receipts — sign, chain, witness, verify
# 3. Trust Web — grant, revoke, verify chain
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

# Run targeted test suites for each primary problem
check "Identity tests pass" cargo test --package agentic-identity -- identity::
check "Crypto tests pass" cargo test --package agentic-identity -- crypto::
check "Receipt tests pass" cargo test --package agentic-identity -- receipt::
check "Trust tests pass" cargo test --package agentic-identity -- trust::
check "Storage tests pass" cargo test --package agentic-identity -- storage::
check "Index tests pass" cargo test --package agentic-identity -- index::
check "Query tests pass" cargo test --package agentic-identity -- query::

echo ""
if [ "$ERRORS" -gt 0 ]; then
  echo -e "${RED}${ERRORS} primary problem test(s) failed${NC}"
  exit 1
else
  echo -e "${GREEN}All primary problem tests passed${NC}"
fi
