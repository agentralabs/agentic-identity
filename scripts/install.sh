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
SERVER_ARGS_TEXT='[]'
MCP_CONFIGURED_CLIENTS=()

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
          MCP_CONFIGURED_CLIENTS+=("${dir}")
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
" && { ok "Merged MCP config into ${dir}"; MCP_CONFIGURED_CLIENTS+=("${dir}"); } || warn "Could not merge MCP config in ${dir}"
        else
          warn "python3 not found — skipping MCP config merge for ${dir}"
        fi
      else
        # Create new config
        ensure_dir "$dir"
        echo "{\"mcpServers\":{\"agentic-identity\":${mcp_entry}}}" | python3 -m json.tool > "$full_path" 2>/dev/null || true
        ok "Created MCP config at ${full_path}"; MCP_CONFIGURED_CLIENTS+=("${dir}")
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

print_client_help() {
  local client
  local configured_count="${#MCP_CONFIGURED_CLIENTS[@]}"

  echo ""
  echo "MCP client summary:"
  if [ "$configured_count" -gt 0 ]; then
    for client in "${MCP_CONFIGURED_CLIENTS[@]}"; do
      echo "  - Configured: ${client}"
    done
  else
    echo "  - No known MCP client config detected (auto-config skipped)"
  fi
  echo ""
  echo "Universal MCP entry (works in any MCP client):"
  echo "  command: ${INSTALL_DIR}/${MCP_BINARY_NAME}"
  echo "  args: ${SERVER_ARGS_TEXT}"
  echo ""
  echo "Quick terminal check:"
  echo "  ${INSTALL_DIR}/${MCP_BINARY_NAME} --help"
  echo "  (Ctrl+C to stop after startup check)"
}

print_profile_help() {
  echo ""
  echo "Install profile: ${PROFILE}"
  case "$PROFILE" in
    desktop)
      echo "  - Binary installed"
      echo "  - Detected MCP client configs merged (Claude/Cursor/Windsurf/VS Code/etc.)"
      ;;
    terminal)
      echo "  - Binary installed"
      echo "  - Detected MCP client configs merged (same as desktop profile)"
      echo "  - Native terminal usage remains available"
      ;;
    server)
      echo "  - Binary installed"
      echo "  - No desktop config files were changed"
      echo "  - Suitable for remote/server hosts"
      echo "  - Server deployments should enforce auth (token/reverse-proxy/TLS)"
      ;;
  esac
}

print_terminal_server_help() {
  echo ""
  echo "Manual MCP config for any client:"
  echo "  command: ${INSTALL_DIR}/${MCP_BINARY_NAME}"
  echo "  args: ${SERVER_ARGS_TEXT}"
  echo ""
  echo "Server authentication setup:"
  echo "  TOKEN=\$(openssl rand -hex 32)"
  echo "  export AGENTIC_TOKEN=\"\$TOKEN\""
  echo "  # Clients must send: Authorization: Bearer \$TOKEN"
  echo ""
  echo "Quick terminal checks:"
  echo "  ${INSTALL_DIR}/${BINARY_NAME} --help"
  echo "  ${INSTALL_DIR}/${MCP_BINARY_NAME} --help"
  echo "  (Ctrl+C to stop after startup check)"
}

print_post_install_next_steps() {
  echo ""
  echo "What happens after installation:"
  echo "  1. agentic-identity was installed as MCP server command: ${INSTALL_DIR}/${MCP_BINARY_NAME}"
  if [ "$PROFILE" = "server" ]; then
    echo "  2. Generate a token (openssl rand -hex 32) and set AGENTIC_TOKEN on the server."
    echo "  3. Start MCP with auth, connect clients, then restart clients."
    echo "  4. Optional feedback: open https://github.com/${REPO}/issues"
  else
    echo "  2. Restart your MCP client/system so it reloads MCP config."
    echo "  3. After restart, confirm 'agentic-identity' appears in your MCP server list."
    echo "  4. Optional feedback: open https://github.com/${REPO}/issues"
  fi
}

print_completion() {
  echo ""
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${GREEN}  AgenticIdentity installed successfully!${NC}"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
  echo "  Version: ${VERSION}"
  echo "  Binary:  ${INSTALL_DIR}/${BINARY_NAME}"
  echo "  MCP:     ${INSTALL_DIR}/${MCP_BINARY_NAME}"

  print_client_help
  print_profile_help

  case "$PROFILE" in
    terminal|server)
      print_terminal_server_help
      ;;
  esac

  print_post_install_next_steps

  echo ""
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
