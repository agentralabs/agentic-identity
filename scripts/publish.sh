#!/bin/bash
set -e

DO_PUBLISH=false
if [ "${1:-}" = "--publish" ]; then
  DO_PUBLISH=true
fi

# Version comes from workspace root (crates use version.workspace = true)
CORE_VERSION="$(grep -m1 '^version\s*=' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
NOTE_DIR="release-notes"
NOTE_FILE="${NOTE_DIR}/v${CORE_VERSION}.md"

ensure_release_note() {
  mkdir -p "${NOTE_DIR}"
  if [ ! -f "${NOTE_FILE}" ]; then
    cat > "${NOTE_FILE}" <<EOF
## TEMPLATE_DRAFT: REPLACE BEFORE PUBLISH

## Executive Summary

AgenticIdentity v${CORE_VERSION} delivers cryptographic identity anchoring for AI agents with signed action receipts, revocable trust, temporal continuity, identity inheritance, competence proofs, and negative capability proofs.

## Business Impact

This release provides production-grade identity primitives that enable AI agents to prove their actions, capabilities, and limitations with cryptographic guarantees.

## Rollout Guidance

Publish core first, validate availability on crates.io, then publish CLI and MCP crates. Verify MCP client registration in staging before broad rollout.

## Source Links

- https://github.com/agentralabs/agentic-identity/compare/v${CORE_VERSION}...HEAD
EOF
    echo "Release note template created at ${NOTE_FILE}."
    echo "Publish gate blocked until you replace template text with final business notes."
    exit 1
  fi
}

validate_release_note() {
  # Must have 4 required headings
  for heading in "Executive Summary" "Business Impact" "Rollout Guidance" "Source Links"; do
    if ! grep -q "## ${heading}" "${NOTE_FILE}"; then
      echo "FAIL: Release note missing required heading: ## ${heading}"
      exit 1
    fi
  done

  # No template markers
  if grep -qi "TEMPLATE_DRAFT" "${NOTE_FILE}"; then
    echo "FAIL: Release note still contains TEMPLATE_DRAFT marker."
    exit 1
  fi

  # No AI slop
  if grep -qi "as an ai" "${NOTE_FILE}"; then
    echo "FAIL: Release note contains forbidden phrase 'as an ai'."
    exit 1
  fi

  # At least 3 paragraphs, each >=120 chars
  PARA_COUNT=0
  while IFS= read -r line; do
    if [ ${#line} -ge 120 ]; then
      PARA_COUNT=$((PARA_COUNT + 1))
    fi
  done < "${NOTE_FILE}"

  if [ "${PARA_COUNT}" -lt 3 ]; then
    echo "FAIL: Release note needs at least 3 narrative paragraphs (>=120 chars each). Found ${PARA_COUNT}."
    exit 1
  fi

  echo "Release note validated."
}

# ── Pre-flight checks ───────────────────────────────────────────────────────

echo "=== AgenticIdentity Publish Pipeline ==="
echo "Core version: ${CORE_VERSION}"
echo ""

ensure_release_note
validate_release_note

echo ""
echo "=== Running tests ==="
cargo test --workspace
echo "Tests passed."

echo ""
echo "=== Checking format ==="
cargo fmt --all -- --check
echo "Format clean."

echo ""
echo "=== Running clippy ==="
cargo clippy --workspace --all-targets -- -D warnings
echo "Clippy clean."

echo ""
echo "=== Dry-run publish (core) ==="
cargo publish -p agentic-identity --dry-run
echo "Core dry-run passed."

echo ""
echo "=== Checking CLI ==="
cargo check -p agentic-identity-cli
echo "CLI check passed."

echo ""
echo "=== Checking MCP ==="
cargo check -p agentic-identity-mcp
echo "MCP check passed."

echo ""
echo "=== Checking FFI ==="
cargo check -p agentic-identity-ffi
echo "FFI check passed."

# ── Publish ──────────────────────────────────────────────────────────────────

if [ "${DO_PUBLISH}" = true ]; then
  echo ""
  echo "=== PUBLISHING to crates.io ==="

  echo "Publishing agentic-identity..."
  cargo publish -p agentic-identity
  echo "Core published. Waiting 45s for crates.io propagation..."
  sleep 45

  echo "Publishing agentic-identity-cli..."
  for attempt in $(seq 1 12); do
    if cargo publish -p agentic-identity-cli 2>&1; then
      echo "CLI published."
      break
    fi
    echo "Attempt ${attempt}/12 failed. Waiting 20s..."
    sleep 20
  done

  echo "Publishing agentic-identity-mcp..."
  for attempt in $(seq 1 12); do
    if cargo publish -p agentic-identity-mcp 2>&1; then
      echo "MCP published."
      break
    fi
    echo "Attempt ${attempt}/12 failed. Waiting 20s..."
    sleep 20
  done

  echo "Publishing agentic-identity-ffi..."
  for attempt in $(seq 1 12); do
    if cargo publish -p agentic-identity-ffi 2>&1; then
      echo "FFI published."
      break
    fi
    echo "Attempt ${attempt}/12 failed. Waiting 20s..."
    sleep 20
  done

  echo ""
  echo "=== Creating GitHub release ==="
  gh release create "v${CORE_VERSION}" \
    --title "AgenticIdentity v${CORE_VERSION}" \
    --notes-file "${NOTE_FILE}"
  echo "GitHub release created."

  echo ""
  echo "=== PUBLISH COMPLETE ==="
else
  echo ""
  echo "=== DRY-RUN COMPLETE ==="
  echo "Add --publish flag to publish for real."
fi
