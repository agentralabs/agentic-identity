#!/usr/bin/env bash
# AgenticIdentity — one-liner install script
# Downloads pre-built binaries when available and auto-configures detected MCP clients.
#
# Usage:
#   curl -fsSL https://agentralabs.tech/install/identity | bash
#
# Options:
#   --version=X.Y.Z   Pin a specific version (default: latest)
#   --dir=/path       Override install directory (default: ~/.local/bin)
#   --profile=<name>  Install profile: desktop | terminal | server (default: desktop)
#   --dry-run         Print actions without executing
#
# What it does:
#   1. Installs aid and agentic-identity-mcp into ~/.local/bin/
#   2. MERGES (NEVER overwrite) MCP config into detected MCP client configs
#   3. Leaves all existing MCP servers untouched
#
# Requirements: curl, jq or python3

set -euo pipefail

# ── Constants ──────────────────────────────────────────────────────────
REPO="agentralabs/agentic-identity"
CLI_BINARY_NAME="aid"
BINARY_NAME="agentic-identity-mcp"
SERVER_KEY="agentic-identity"
INSTALL_DIR="${AGENTRA_INSTALL_DIR:-$HOME/.local/bin}"
INSTALL_DIR_EXPLICIT=false
VERSION="latest"
PROFILE="${AGENTRA_INSTALL_PROFILE:-desktop}"
DRY_RUN=false
BAR_ONLY="${AGENTRA_INSTALL_BAR_ONLY:-1}"
MCP_ENTRYPOINT=""
PLATFORM=""
HOST_OS=""
SERVER_ARGS_JSON='[]'
SERVER_ARGS_TEXT='[]'
SERVER_CHECK_CMD_SUFFIX=""
MCP_CONFIGURED_CLIENTS=()
MCP_SCANNED_CONFIG_FILES=()

# ── Parse arguments ──────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --version=*)
            VERSION="${1#*=}"
            shift
            ;;
        --version)
            VERSION="${2:-}"
            shift 2
            ;;
        --dir=*)
            INSTALL_DIR="${1#*=}"
            INSTALL_DIR_EXPLICIT=true
            shift
            ;;
        --dir)
            INSTALL_DIR="${2:-}"
            INSTALL_DIR_EXPLICIT=true
            shift 2
            ;;
        --profile=*)
            PROFILE="${1#*=}"
            shift
            ;;
        --profile)
            PROFILE="${2:-}"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            echo "Usage: install.sh [--version X.Y.Z|--version=X.Y.Z] [--dir /path|--dir=/path] [--profile desktop|terminal|server|--profile=desktop|terminal|server] [--dry-run]"
            exit 0
            ;;
        desktop|terminal|server)
            PROFILE="$1"
            shift
            ;;
        *)
            echo "Error: unknown option '$1'" >&2
            exit 1
            ;;
    esac
done

MCP_ENTRYPOINT="${INSTALL_DIR}/${BINARY_NAME}"

# ── Progress output (bar-only mode by default) ───────────────────────
exec 3>&1
if [ "$BAR_ONLY" = "1" ] && [ "$DRY_RUN" = false ]; then
    exec 1>/dev/null
fi

PROGRESS=0
BAR_WIDTH=36

draw_progress() {
    local percent="$1"
    local label="$2"
    local filled=$((percent * BAR_WIDTH / 100))
    local empty=$((BAR_WIDTH - filled))
    printf "\r[" >&3
    printf "%${filled}s" "" | tr " " "#" >&3
    printf "%${empty}s" "" | tr " " "-" >&3
    printf "] %3d%% %s" "$percent" "$label" >&3
}

set_progress() {
    local percent="$1"
    local label="$2"
    PROGRESS="$percent"
    draw_progress "$percent" "$label"
}

finish_progress() {
    printf "\n" >&3
}

run_with_progress() {
    local start="$1"
    local end="$2"
    local label="$3"
    shift 3

    local log_file
    log_file="$(mktemp)"
    local current="$start"

    set_progress "$current" "$label"
    "$@" >"$log_file" 2>&1 &
    local cmd_pid=$!

    while kill -0 "$cmd_pid" 2>/dev/null; do
        if [ "$current" -lt $((end - 1)) ]; then
            current=$((current + 1))
            set_progress "$current" "$label"
        fi
        sleep 0.2
    done

    if ! wait "$cmd_pid"; then
        finish_progress
        echo "Install failed during: ${label}" >&3
        tail -n 120 "$log_file" >&3 || true
        rm -f "$log_file"
        return 1
    fi

    rm -f "$log_file"
    set_progress "$end" "$label"
}

validate_profile() {
    case "$PROFILE" in
        desktop|terminal|server) ;;
        *)
            echo "Error: invalid profile '${PROFILE}'. Use desktop, terminal, or server." >&2
            exit 1
            ;;
    esac
}

# ── Dependencies ──────────────────────────────────────────────────────
check_deps() {
    if ! command -v curl >/dev/null 2>&1; then
        echo "Error: 'curl' is required but not installed." >&2
        exit 1
    fi
    if ! command -v jq >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
        echo "Error: JSON merge requires 'jq' or 'python3'." >&2
        echo "  Install jq (preferred) or python3, then rerun." >&2
        exit 1
    fi
}

# ── Platform detection ────────────────────────────────────────────────
detect_platform() {
    local os arch
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"

    case "$os" in
        darwin) HOST_OS="darwin" ;;
        linux) HOST_OS="linux" ;;
        *)
            echo "Error: Unsupported OS: $os" >&2
            exit 1
            ;;
    esac

    case "$arch" in
        x86_64|amd64) arch="x86_64" ;;
        arm64|aarch64) arch="aarch64" ;;
        *)
            echo "Error: Unsupported architecture: $arch" >&2
            exit 1
            ;;
    esac

    if [ "$HOST_OS" = "darwin" ]; then
        PLATFORM="${arch}-apple-darwin"
    else
        PLATFORM="${arch}-unknown-linux-gnu"
    fi
}

# ── Releases ──────────────────────────────────────────────────────────
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
        | jq -r '.tag_name // empty' 2>/dev/null || true
}

download_binaries() {
    local version="$1"
    local version_tag="$version"
    local tarball="${CLI_BINARY_NAME}-${PLATFORM}.tar.gz"
    local url="https://github.com/${REPO}/releases/download/${version_tag}/${tarball}"

    if [ "$DRY_RUN" = true ]; then
        echo "  [dry-run] Would download: ${url}"
        echo "  [dry-run] Would install to: ${INSTALL_DIR}/${CLI_BINARY_NAME}"
        echo "  [dry-run] Would install to: ${INSTALL_DIR}/${BINARY_NAME}"
        return 0
    fi

    local tmpdir
    tmpdir="$(mktemp -d)"
    mkdir -p "$INSTALL_DIR"

    if ! curl -fsSL "$url" -o "${tmpdir}/${tarball}" 2>/dev/null; then
        rm -rf "$tmpdir"
        return 1
    fi

    if ! tar xzf "${tmpdir}/${tarball}" -C "$tmpdir"; then
        rm -rf "$tmpdir"
        return 1
    fi

    local cli_src
    local mcp_src
    cli_src="$(find "$tmpdir" -type f -name "${CLI_BINARY_NAME}" | head -n 1)"
    mcp_src="$(find "$tmpdir" -type f -name "${BINARY_NAME}" | head -n 1)"

    if [ -z "$cli_src" ] || [ -z "$mcp_src" ]; then
        echo "Release artifact missing required binaries (need ${CLI_BINARY_NAME} and ${BINARY_NAME})." >&2
        rm -rf "$tmpdir"
        return 1
    fi

    cp "$cli_src" "${INSTALL_DIR}/${CLI_BINARY_NAME}"
    cp "$mcp_src" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod +x "${INSTALL_DIR}/${CLI_BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    rm -rf "$tmpdir"
    return 0
}

# ── Source fallback ───────────────────────────────────────────────────
install_from_source() {
    local git_url="https://github.com/${REPO}.git"

    if [ "$DRY_RUN" = true ]; then
        echo "  [dry-run] Would clone: ${git_url}"
        echo "  [dry-run] Would build: cargo build --release --package agentic-identity-cli --package agentic-identity-mcp"
        echo "  [dry-run] Would install to: ${INSTALL_DIR}/${CLI_BINARY_NAME}"
        echo "  [dry-run] Would install to: ${INSTALL_DIR}/${BINARY_NAME}"
        return 0
    fi

    if ! command -v cargo >/dev/null 2>&1; then
        echo "Error: release artifacts are unavailable and cargo is not installed." >&2
        echo "Install Rust/Cargo first: https://rustup.rs" >&2
        exit 1
    fi
    if ! command -v git >/dev/null 2>&1; then
        echo "Error: git is required for source fallback." >&2
        exit 1
    fi

    local tmpdir
    tmpdir="$(mktemp -d)"

    run_with_progress 45 55 "Cloning source" \
        git clone --depth 1 "$git_url" "${tmpdir}/agentic-identity"

    (
        cd "${tmpdir}/agentic-identity"
        run_with_progress 55 85 "Building release binaries" \
            cargo build --release --package agentic-identity-cli --package agentic-identity-mcp
    )

    mkdir -p "$INSTALL_DIR"
    cp "${tmpdir}/agentic-identity/target/release/${CLI_BINARY_NAME}" "${INSTALL_DIR}/${CLI_BINARY_NAME}"
    cp "${tmpdir}/agentic-identity/target/release/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod +x "${INSTALL_DIR}/${CLI_BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    rm -rf "$tmpdir"
}

# ── Config merge helpers ──────────────────────────────────────────────
record_mcp_client() {
    local client_name="$1"
    MCP_CONFIGURED_CLIENTS+=("$client_name")
}

record_mcp_config_path() {
    local config_file="$1"
    MCP_SCANNED_CONFIG_FILES+=("$config_file")
}

is_known_mcp_config_path() {
    local config_file="$1"
    local known
    for known in "${MCP_SCANNED_CONFIG_FILES[@]}"; do
        if [ "$known" = "$config_file" ]; then
            return 0
        fi
    done
    return 1
}

merge_config() {
    local config_file="$1"
    local config_dir
    config_dir="$(dirname "$config_file")"

    if [ "$DRY_RUN" = true ]; then
        echo "    [dry-run] Would merge MCP entry into: ${config_file}"
        return
    fi

    mkdir -p "$config_dir"

    if command -v python3 >/dev/null 2>&1; then
        MCP_ENTRYPOINT="$MCP_ENTRYPOINT" \
        SERVER_ARGS_JSON="$SERVER_ARGS_JSON" \
        SERVER_KEY="$SERVER_KEY" \
        PROFILE="$PROFILE" \
        AGENTIC_TOKEN="${AGENTIC_TOKEN:-}" \
        CONFIG_FILE="$config_file" \
        python3 - <<'PY'
import json
import os

config_file = os.environ["CONFIG_FILE"]
entry = {
    "command": os.environ["MCP_ENTRYPOINT"],
    "args": json.loads(os.environ["SERVER_ARGS_JSON"]),
    "env": {},
}

if os.environ.get("PROFILE") == "server" and os.environ.get("AGENTIC_TOKEN"):
    entry["env"]["AGENTIC_TOKEN"] = os.environ["AGENTIC_TOKEN"]

try:
    with open(config_file, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    data = {}

if not isinstance(data, dict):
    data = {}

data.setdefault("mcpServers", {})
data["mcpServers"][os.environ["SERVER_KEY"]] = entry

with open(config_file, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
    else
        local tmp_file
        tmp_file="$(mktemp)"
        if [ -f "$config_file" ]; then
            cp "$config_file" "$tmp_file"
        else
            echo '{}' > "$tmp_file"
        fi

        jq \
          --arg key "$SERVER_KEY" \
          --arg cmd "$MCP_ENTRYPOINT" \
          --argjson args "$SERVER_ARGS_JSON" \
          '. as $root | if ($root|type) != "object" then {} else . end
           | .mcpServers = (if (.mcpServers|type) == "object" then .mcpServers else {} end)
           | .mcpServers[$key] = {command: $cmd, args: $args, env: {}}' \
          "$tmp_file" > "$config_file"
        rm -f "$tmp_file"
    fi
}

configure_json_client_if_present() {
    local client_name="$1"
    local config_file="$2"
    local detect_path="${3:-$(dirname "$config_file")}"

    if [ -f "$config_file" ] || [ -d "$detect_path" ]; then
        echo "  ${client_name}..."
        merge_config "$config_file"
        echo "  Done"
        record_mcp_client "$client_name"
        record_mcp_config_path "$config_file"
    fi
}

configure_claude_desktop() {
    local config_file
    case "$HOST_OS" in
        darwin)
            config_file="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
            ;;
        linux)
            config_file="${XDG_CONFIG_HOME:-$HOME/.config}/Claude/claude_desktop_config.json"
            ;;
        *)
            return
            ;;
    esac

    echo "  Claude Desktop..."
    merge_config "$config_file"
    echo "  Done"
    record_mcp_client "Claude Desktop"
    record_mcp_config_path "$config_file"
}

configure_claude_code() {
    local config_file="$HOME/.claude/mcp.json"
    if [ -d "$HOME/.claude" ] || [ -f "$config_file" ]; then
        echo "  Claude Code..."
        merge_config "$config_file"
        echo "  Done"
        record_mcp_client "Claude Code"
        record_mcp_config_path "$config_file"
    fi
}

configure_codex() {
    local codex_home="${CODEX_HOME:-$HOME/.codex}"
    local codex_config="${codex_home}/config.toml"

    if ! command -v codex >/dev/null 2>&1 && [ ! -d "$codex_home" ] && [ ! -f "$codex_config" ]; then
        return
    fi

    echo "  Codex..."
    if [ "$DRY_RUN" = true ]; then
        echo "    [dry-run] Would run: codex mcp add ${SERVER_KEY} -- ${MCP_ENTRYPOINT}"
    elif command -v codex >/dev/null 2>&1; then
        codex mcp remove "$SERVER_KEY" >/dev/null 2>&1 || true
        if ! codex mcp add "$SERVER_KEY" -- "$MCP_ENTRYPOINT" >/dev/null 2>&1; then
            echo "    Warning: could not auto-configure Codex via CLI."
            echo "    Run: codex mcp add ${SERVER_KEY} -- ${MCP_ENTRYPOINT}"
            return
        fi
    else
        mkdir -p "$codex_home"
        if [ ! -f "$codex_config" ]; then
            touch "$codex_config"
        fi
        {
            echo ""
            echo "[mcp_servers.${SERVER_KEY}]"
            echo "command = \"${MCP_ENTRYPOINT}\""
            echo "args = []"
        } >> "$codex_config"
    fi
    echo "  Done"
    record_mcp_client "Codex"
    record_mcp_config_path "$codex_config"
}

configure_generic_mcp_json_files() {
    local root
    local file
    local roots=(
        "$HOME/.config"
        "$HOME/Library/Application Support"
        "$HOME/.cursor"
        "$HOME/.windsurf"
        "$HOME/.codeium"
        "$HOME/.claude"
    )

    for root in "${roots[@]}"; do
        [ -d "$root" ] || continue
        while IFS= read -r file; do
            [ -n "$file" ] || continue
            if is_known_mcp_config_path "$file"; then
                continue
            fi
            echo "  Generic MCP config (${file})..."
            merge_config "$file"
            echo "  Done"
            record_mcp_client "Generic MCP JSON"
            record_mcp_config_path "$file"
        done < <(find "$root" -maxdepth 6 -type f \
            \( -name "mcp.json" -o -name "mcp_config.json" -o -name "claude_desktop_config.json" -o -name "cline_mcp_settings.json" \) \
            2>/dev/null | sort -u)
    done
}

merge_mcp_config() {
    # Merge agentic-identity into MCP config — NEVER overwrite existing servers.
    configure_claude_desktop
    configure_claude_code
    configure_json_client_if_present "Cursor" "$HOME/.cursor/mcp.json" "$HOME/.cursor"
    configure_json_client_if_present "Windsurf" "$HOME/.windsurf/mcp.json" "$HOME/.windsurf"
    if [ "$HOST_OS" = "darwin" ]; then
        configure_json_client_if_present "VS Code" "$HOME/Library/Application Support/Code/User/mcp.json" "$HOME/Library/Application Support/Code/User"
        configure_json_client_if_present "VS Code + Cline" "$HOME/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" "$HOME/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev"
    else
        configure_json_client_if_present "VS Code" "${XDG_CONFIG_HOME:-$HOME/.config}/Code/User/mcp.json" "${XDG_CONFIG_HOME:-$HOME/.config}/Code/User"
        configure_json_client_if_present "VS Code + Cline" "${XDG_CONFIG_HOME:-$HOME/.config}/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" "${XDG_CONFIG_HOME:-$HOME/.config}/Code/User/globalStorage/saoudrizwan.claude-dev"
    fi
    configure_codex
    configure_generic_mcp_json_files
}

# ── Output helpers ────────────────────────────────────────────────────
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
    echo "  command: ${MCP_ENTRYPOINT}"
    echo "  args: ${SERVER_ARGS_TEXT}"
    echo ""
    echo "Quick terminal check:"
    echo "  ${INSTALL_DIR}/${BINARY_NAME}${SERVER_CHECK_CMD_SUFFIX}"
    echo "  (Ctrl+C to stop after startup check)"
}

print_profile_help() {
    echo ""
    echo "Install profile: ${PROFILE}"
    case "$PROFILE" in
        desktop)
            echo "  - Binaries installed (aid + agentic-identity-mcp)"
            echo "  - Detected MCP client configs merged (Claude/Codex/Cursor/Windsurf/VS Code/etc.)"
            ;;
        terminal)
            echo "  - Binaries installed (aid + agentic-identity-mcp)"
            echo "  - Detected MCP client configs merged (same as desktop profile)"
            echo "  - Native terminal usage remains available"
            ;;
        server)
            echo "  - Binaries installed (aid + agentic-identity-mcp)"
            echo "  - No desktop config files were changed"
            echo "  - Suitable for remote/server hosts"
            echo "  - Server deployments should enforce auth (token/reverse-proxy/TLS)"
            ;;
    esac
}

print_terminal_server_help() {
    echo ""
    echo "Manual MCP config for any client:"
    echo "  command: ${MCP_ENTRYPOINT}"
    echo "  args: ${SERVER_ARGS_TEXT}"
    echo ""
    echo "Server authentication setup:"
    echo "  TOKEN=\$(openssl rand -hex 32)"
    echo "  export AGENTIC_TOKEN=\"\$TOKEN\""
    echo "  # Clients must send: Authorization: Bearer \$TOKEN"
    echo ""
    echo "Quick terminal checks:"
    echo "  ${INSTALL_DIR}/${CLI_BINARY_NAME} --help"
    echo "  ${INSTALL_DIR}/${BINARY_NAME}${SERVER_CHECK_CMD_SUFFIX}"
    echo "  (Ctrl+C to stop after startup check)"
}

print_post_install_next_steps() {
    echo "" >&3
    echo "What happens after installation:" >&3
    echo "  1. ${SERVER_KEY} was installed as MCP server command: ${MCP_ENTRYPOINT}" >&3
    if [ "$PROFILE" = "server" ]; then
        echo "  2. Generate a token (openssl rand -hex 32) and set AGENTIC_TOKEN on the server." >&3
        echo "  3. Start MCP with auth, connect clients, then restart clients." >&3
        echo "  4. Optional feedback: open https://github.com/${REPO}/issues" >&3
    elif [ "$PROFILE" = "desktop" ]; then
        echo "  2. Restart any configured MCP client so it reloads MCP config." >&3
        echo "  3. After restart, confirm '${SERVER_KEY}' appears in your MCP server list." >&3
        echo "  4. Optional feedback: open https://github.com/${REPO}/issues" >&3
    else
        echo "  2. Restart your MCP client/system so it reloads MCP config." >&3
        echo "  3. After restart, confirm '${SERVER_KEY}' appears in your MCP server list." >&3
        echo "  4. Optional feedback: open https://github.com/${REPO}/issues" >&3
    fi
}

check_path() {
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo "" >&3
        echo "Note: Add ${INSTALL_DIR} to your PATH if not already:" >&3
        echo "  export PATH=\"${INSTALL_DIR}:\$PATH\"" >&3
        echo "" >&3
        echo "Add this line to your shell profile to make it permanent." >&3
    fi
}

# ── Main ──────────────────────────────────────────────────────────────
main() {
    set_progress 0 "Starting installer"
    echo "AgenticIdentity Installer"
    echo "========================="
    echo ""

    set_progress 10 "Checking prerequisites"
    check_deps

    set_progress 20 "Detecting platform"
    detect_platform
    validate_profile

    if [ "$INSTALL_DIR_EXPLICIT" = false ] && [ -n "${AGENTRA_INSTALL_DIR:-}" ]; then
        INSTALL_DIR="${AGENTRA_INSTALL_DIR}"
    fi
    MCP_ENTRYPOINT="${INSTALL_DIR}/${BINARY_NAME}"

    echo "Platform: ${PLATFORM}"
    echo "Profile: ${PROFILE}"
    echo "Install dir: ${INSTALL_DIR}"

    set_progress 30 "Resolving release"

    local resolved_version="$VERSION"
    if [ "$resolved_version" = "latest" ]; then
        resolved_version="$(get_latest_version)"
    fi

    local installed_from_release=false
    if [ -n "$resolved_version" ] && [ "$resolved_version" != "null" ]; then
        echo "Version: ${resolved_version}"
        if download_binaries "$resolved_version"; then
            installed_from_release=true
            set_progress 70 "Release binary installed"
        else
            echo "Release artifact not found for ${resolved_version}/${PLATFORM}; using source fallback."
        fi
    else
        echo "No GitHub release found; using source fallback."
    fi

    if [ "$installed_from_release" = false ]; then
        install_from_source
    fi

    set_progress 88 "Finalizing binaries"
    if [ "$DRY_RUN" = false ]; then
        chmod +x "${INSTALL_DIR}/${CLI_BINARY_NAME}" 2>/dev/null || true
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null || true
    fi

    set_progress 90 "Applying profile setup"
    if [ "$PROFILE" = "desktop" ] || [ "$PROFILE" = "terminal" ]; then
        echo ""
        echo "Configuring MCP clients..."
        merge_mcp_config
        print_client_help
    else
        print_terminal_server_help
    fi

    print_profile_help

    set_progress 100 "Install complete"
    finish_progress
    echo "Install complete: AgenticIdentity (${PROFILE})" >&3
    echo "" >&3
    echo "Done! AgenticIdentity install completed." >&3
    if [ "$PROFILE" = "desktop" ]; then
        echo "Restart any configured MCP client to activate." >&3
    fi

    print_post_install_next_steps
    check_path
}

main "$@"
