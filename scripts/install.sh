#!/usr/bin/env bash
# install.sh — AgenticIdentity Universal Installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/agentralabs/agentic-identity/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/agentralabs/agentic-identity/main/install.sh | bash -s -- --profile terminal
#
# Profiles:
#   desktop  (default) — Install binaries + auto-merge MCP config
#   terminal           — Install binaries only
#   server             — Install binaries + auth gate
#
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Constants ────────────────────────────────────────────────────────────────
REPO="agentralabs/agentic-identity"
BINARY_NAME="aid"
MCP_BINARY_NAME="agentic-identity-mcp"
VERSION="0.1.0"
INSTALL_DIR="${HOME}/.local/bin"
AGENTIC_DIR="${HOME}/.agentic"

# ── Profile Detection ────────────────────────────────────────────────────────
PROFILE="${1:-desktop}"
case "$PROFILE" in
  --profile) PROFILE="${2:-desktop}" ;;
  desktop|terminal|server) ;;
  *) PROFILE="desktop" ;;
esac

# ── Functions ────────────────────────────────────────────────────────────────

info()  { echo -e "${BLUE}[info]${NC} $*"; }
ok()    { echo -e "${GREEN}[ok]${NC} $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC} $*"; }
err()   { echo -e "${RED}[error]${NC} $*" >&2; }

detect_platform() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    arm64|aarch64) arch="aarch64" ;;
    *) err "Unsupported architecture: $arch"; exit 1 ;;
  esac
  case "$os" in
    darwin) PLATFORM="${arch}-apple-darwin" ;;
    linux)  PLATFORM="${arch}-unknown-linux-gnu" ;;
    *)      err "Unsupported OS: $os"; exit 1 ;;
  esac
}

ensure_dir() {
  mkdir -p "$1"
}

try_download_release() {
  local url="https://github.com/${REPO}/releases/download/v${VERSION}"
  local tarball="${BINARY_NAME}-${PLATFORM}.tar.gz"

  info "Trying pre-built release for ${PLATFORM}..."
  if curl -fsSL "${url}/${tarball}" -o "/tmp/${tarball}" 2>/dev/null; then
    tar -xzf "/tmp/${tarball}" -C "${INSTALL_DIR}"
    rm -f "/tmp/${tarball}"
    ok "Installed pre-built binaries"
    return 0
  fi
  return 1
}

build_from_source() {
  info "No pre-built release found. Building from source..."

  if ! command -v cargo &>/dev/null; then
    err "Rust toolchain not found. Install from https://rustup.rs"
    exit 1
  fi

  local tmpdir
  tmpdir="$(mktemp -d)"
  trap "rm -rf ${tmpdir}" EXIT

  info "Cloning repository..."
  git clone --depth 1 "https://github.com/${REPO}.git" "${tmpdir}/agentic-identity"

  info "Building release binaries..."
  cd "${tmpdir}/agentic-identity"
  cargo build --release --package agentic-identity-cli --package agentic-identity-mcp

  cp "target/release/${BINARY_NAME}" "${INSTALL_DIR}/"
  cp "target/release/${MCP_BINARY_NAME}" "${INSTALL_DIR}/"

  ok "Built and installed from source"
}

merge_mcp_config() {
  # Merge agentic-identity into MCP config — NEVER overwrite existing servers
  local config_dirs=(
    "${HOME}/.config/claude"
    "${HOME}/.cursor"
    "${HOME}/.config/Code/User"
    "${HOME}/.windsurf"
  )
  local config_file="claude_desktop_config.json"

  local mcp_entry
  mcp_entry=$(cat <<'MCPJSON'
{
  "command": "INSTALL_DIR/agentic-identity-mcp",
  "args": [],
  "env": {}
}
MCPJSON
)
  mcp_entry="${mcp_entry//INSTALL_DIR/${INSTALL_DIR}}"

  for dir in "${config_dirs[@]}"; do
    local full_path="${dir}/${config_file}"
    if [ -d "$dir" ]; then
      if [ -f "$full_path" ]; then
        # Check if already configured
        if grep -q "agentic-identity-mcp" "$full_path" 2>/dev/null; then
          info "MCP config already contains agentic-identity in ${dir}"
          continue
        fi
        # Merge into existing config using Python (available on macOS/Linux)
        if command -v python3 &>/dev/null; then
          python3 -c "
import json, sys
try:
    with open('${full_path}', 'r') as f:
        config = json.load(f)
except:
    config = {}
config.setdefault('mcpServers', {})
config['mcpServers']['agentic-identity'] = json.loads('''${mcp_entry}''')
with open('${full_path}', 'w') as f:
    json.dump(config, f, indent=2)
print('Merged agentic-identity into ${full_path}')
" && ok "Merged MCP config into ${dir}" || warn "Could not merge MCP config in ${dir}"
        else
          warn "python3 not found — skipping MCP config merge for ${dir}"
        fi
      else
        # Create new config
        ensure_dir "$dir"
        echo "{\"mcpServers\":{\"agentic-identity\":${mcp_entry}}}" | python3 -m json.tool > "$full_path" 2>/dev/null || true
        ok "Created MCP config at ${full_path}"
      fi
    fi
  done
}

check_path() {
  if [[ ":${PATH}:" != *":${INSTALL_DIR}:"* ]]; then
    warn "${INSTALL_DIR} is not in your PATH"
    echo ""
    echo "  Add to your shell profile:"
    echo "    export PATH=\"\${HOME}/.local/bin:\${PATH}\""
    echo ""
  fi
}

print_completion() {
  echo ""
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${GREEN}  AgenticIdentity installed successfully!${NC}"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
  echo "  Profile: ${PROFILE}"
  echo "  Version: ${VERSION}"
  echo "  Binary:  ${INSTALL_DIR}/${BINARY_NAME}"
  echo "  MCP:     ${INSTALL_DIR}/${MCP_BINARY_NAME}"
  echo ""

  case "$PROFILE" in
    desktop)
      echo "  Next steps:"
      echo "    1. Restart your AI editor (Claude Desktop, Cursor, etc.)"
      echo "    2. Ask your AI agent: \"Create a new identity for me\""
      echo ""
      ;;
    terminal)
      echo "  Next steps:"
      echo "    1. Run: aid init"
      echo "    2. Run: aid show"
      echo ""
      echo "  For MCP integration, add to your config:"
      echo "    \"agentic-identity\": {"
      echo "      \"command\": \"${INSTALL_DIR}/${MCP_BINARY_NAME}\""
      echo "    }"
      echo ""
      ;;
    server)
      echo "  Next steps:"
      echo "    1. Set AGENTIC_TOKEN environment variable"
      echo "    2. Run: ${MCP_BINARY_NAME}"
      echo ""
      ;;
  esac

  echo -e "  ${BLUE}Docs:${NC} https://agentralabs.tech/docs"
  echo -e "  ${BLUE}Repo:${NC} https://github.com/${REPO}"
  echo ""
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
  echo ""
  echo -e "${CYAN}  AgenticIdentity Installer${NC}"
  echo -e "  Profile: ${PROFILE} | Version: ${VERSION}"
  echo ""

  detect_platform
  info "Platform: ${PLATFORM}"

  ensure_dir "${INSTALL_DIR}"
  ensure_dir "${AGENTIC_DIR}"

  # Install binaries
  if ! try_download_release; then
    build_from_source
  fi

  chmod +x "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null || true
  chmod +x "${INSTALL_DIR}/${MCP_BINARY_NAME}" 2>/dev/null || true

  # Profile-specific setup
  case "$PROFILE" in
    desktop)
      merge_mcp_config
      ;;
    terminal)
      info "Terminal profile — skipping MCP config"
      ;;
    server)
      info "Server profile — auth gate enabled"
      if [ -z "${AGENTIC_TOKEN:-}" ]; then
        warn "AGENTIC_TOKEN not set — server will require it at runtime"
      fi
      ;;
  esac

  check_path
  print_completion
}

main "$@"
