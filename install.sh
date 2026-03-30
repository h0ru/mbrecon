#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  mbrecon — installer
#  https://github.com/h0ru/mbrecon
# ─────────────────────────────────────────────────────────────

set -e

REPO_URL="https://raw.githubusercontent.com/h0ru/mbrecon/refs/heads/main/mbrecon.py"
INSTALL_DIR="$(pwd)"
SCRIPT_NAME="mbrecon.py"
MIN_PYTHON="3.8"

# ── COLORS ───────────────────────────────────────────────────
CYAN='\033[96m'
GREEN='\033[92m'
YELLOW='\033[93m'
RED='\033[91m'
GRAY='\033[90m'
BOLD='\033[1m'
RESET='\033[0m'

ok()   { echo -e "  ${BOLD}${GREEN}[✓]${RESET}  $1"; }
fail() { echo -e "  ${BOLD}${RED}[✗]${RESET}  $1"; exit 1; }
info() { echo -e "  ${CYAN}[~]${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}[!]${RESET}  $1"; }

center() {
    local text="$1"
    local width=60
    local len=${#text}
    local pad=$(( (width - len) / 2 ))
    printf "%${pad}s%s\n" "" "$text"
}

# ── BANNER ───────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}$(printf '═%.0s' {1..60})${RESET}"
echo -e "${BOLD}${CYAN}$(center 'MBRECON — Installer')${RESET}"
echo -e "${GRAY}$(center 'https://github.com/h0ru/mbrecon')${RESET}"
echo -e "${BOLD}${CYAN}$(printf '─%.0s' {1..60})${RESET}"
echo ""

# ── STEP 1: CHECK OS ─────────────────────────────────────────
info "Checking operating system..."
OS="$(uname -s)"
case "$OS" in
    Linux*)   ok "Linux detected" ;;
    Darwin*)  ok "macOS detected" ;;
    *)        fail "Unsupported OS: $OS" ;;
esac

# ── STEP 2: CHECK PYTHON ─────────────────────────────────────
info "Checking Python version (required >= ${MIN_PYTHON})..."

PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        VER=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        MAJOR=$(echo "$VER" | cut -d. -f1)
        MINOR=$(echo "$VER" | cut -d. -f2)
        REQ_MAJOR=$(echo "$MIN_PYTHON" | cut -d. -f1)
        REQ_MINOR=$(echo "$MIN_PYTHON" | cut -d. -f2)
        if [ "$MAJOR" -gt "$REQ_MAJOR" ] || { [ "$MAJOR" -eq "$REQ_MAJOR" ] && [ "$MINOR" -ge "$REQ_MINOR" ]; }; then
            PYTHON="$cmd"
            ok "Found $cmd $VER"
            break
        else
            warn "$cmd $VER found but version < ${MIN_PYTHON}, skipping"
        fi
    fi
done

[ -z "$PYTHON" ] && fail "Python >= ${MIN_PYTHON} not found. Install it from https://python.org"

# ── STEP 3: CHECK PIP ────────────────────────────────────────
info "Checking pip..."
PIP=""
for cmd in pip3 pip; do
    if command -v "$cmd" &>/dev/null; then
        PIP="$cmd"
        ok "Found $cmd"
        break
    fi
done

if [ -z "$PIP" ]; then
    warn "pip not found — attempting to install via ensurepip..."
    "$PYTHON" -m ensurepip --upgrade 2>/dev/null || fail "pip installation failed. Install pip manually."
    PIP="$PYTHON -m pip"
fi

# ── STEP 4: INSTALL PYMODBUS ─────────────────────────────────
info "Installing pymodbus..."
if $PIP install pymodbus --quiet --break-system-packages 2>/dev/null || \
   $PIP install pymodbus --quiet 2>/dev/null; then
    ok "pymodbus installed"
else
    fail "Failed to install pymodbus. Try manually: pip install pymodbus"
fi

# ── STEP 5: DOWNLOAD MBRECON ─────────────────────────────────
info "Downloading mbrecon.py from GitHub..."

TMP_FILE="$(mktemp /tmp/mbrecon.XXXXXX.py)"

if command -v curl &>/dev/null; then
    curl -sSL "$REPO_URL" -o "$TMP_FILE" || fail "Download failed (curl). Check your connection."
elif command -v wget &>/dev/null; then
    wget -qO "$TMP_FILE" "$REPO_URL" || fail "Download failed (wget). Check your connection."
else
    fail "Neither curl nor wget found. Install one and retry."
fi

ok "Downloaded mbrecon.py"

# ── STEP 6: VALIDATE DOWNLOAD ────────────────────────────────
info "Validating downloaded file..."
"$PYTHON" -c "import ast; ast.parse(open('$TMP_FILE').read())" 2>/dev/null \
    || fail "Downloaded file failed syntax check. The file may be corrupted or the URL has changed."
ok "Syntax check passed"

# ── STEP 7: INSTALL ──────────────────────────────────────────
info "Installing to ${INSTALL_DIR}/${SCRIPT_NAME}..."

cp "$TMP_FILE" "${INSTALL_DIR}/${SCRIPT_NAME}" \
    || fail "Could not write to ${INSTALL_DIR}."
chmod +x "${INSTALL_DIR}/${SCRIPT_NAME}"
sed -i.bak "1s|.*|#!$(command -v $PYTHON)|" "${INSTALL_DIR}/${SCRIPT_NAME}" 2>/dev/null \
    && rm -f "${INSTALL_DIR}/${SCRIPT_NAME}.bak" || true

rm -f "$TMP_FILE"
ok "Installed to ${INSTALL_DIR}/${SCRIPT_NAME}"

# ── DONE ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}$(printf '─%.0s' {1..60})${RESET}"
ok "mbrecon installed successfully"
echo ""
echo -e "  ${GRAY}Run with:${RESET}"
echo -e "  ${BOLD}  python3 mbrecon.py <host>${RESET}"
echo -e "  ${BOLD}  python3 mbrecon.py <host> --port 502 --device-id 1${RESET}"
echo ""
echo -e "${BOLD}${CYAN}$(printf '═%.0s' {1..60})${RESET}"
echo ""
