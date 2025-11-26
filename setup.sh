#!/usr/bin/env bash
set -euo pipefail

# --------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------
INSTALL_DIR="/usr/local/sbin/noip-renew"
LOG_FILE="/var/log/noip-renew.log"

# User that should own files / cron job
OWNER="${SUDO_USER:-$USER}"

# --------------------------------------------------------------------
# Helper functions
# --------------------------------------------------------------------
info()  { echo "[INFO]  $*"; }
warn()  { echo "[WARN]  $*"; }
error() { echo "[ERROR] $*" >&2; }

# --------------------------------------------------------------------
# Step 0: Check Python 3 version (>= 3.7)
# --------------------------------------------------------------------
info "Step 0: Checking Python 3 version..."

if ! command -v python3 >/dev/null 2>&1; then
    error "python3 not found. Please install Python 3.7 or higher and rerun this script."
    exit 1
fi

PYTHON_BIN="$(command -v python3)"
PYTHON_VERSION="$("$PYTHON_BIN" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"

PY_MAJOR="$(echo "$PYTHON_VERSION" | cut -d. -f1)"
PY_MINOR="$(echo "$PYTHON_VERSION" | cut -d. -f2)"

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 7 ]; }; then
    error "Python 3.7 or higher is required. Detected version: $PYTHON_VERSION"
    exit 1
fi

info "Detected Python version: $PYTHON_VERSION (OK)"

# --------------------------------------------------------------------
# Step 1: Ensure Python dependencies are installed
# --------------------------------------------------------------------
info "Step 1: Checking Python dependencies (requests, beautifulsoup4, pyotp)..."

MISSING_PKGS=()

# requests
if ! "$PYTHON_BIN" -c 'import requests' >/dev/null 2>&1; then
    MISSING_PKGS+=("requests")
fi

# beautifulsoup4 → module name bs4
if ! "$PYTHON_BIN" -c 'import bs4' >/dev/null 2>&1; then
    MISSING_PKGS+=("beautifulsoup4")
fi

# pyotp
if ! "$PYTHON_BIN" -c 'import pyotp' >/dev/null 2>&1; then
    MISSING_PKGS+=("pyotp")
fi

if [ "${#MISSING_PKGS[@]}" -gt 0 ]; then
    info "Installing missing Python packages: ${MISSING_PKGS[*]}"
    "$PYTHON_BIN" -m pip install "${MISSING_PKGS[@]}"
else
    info "All required Python packages are already installed."
fi

# --------------------------------------------------------------------
# Step 2: Create /var/log/noip-renew.log if missing
# --------------------------------------------------------------------
info "Step 2: Preparing log file at $LOG_FILE..."

if [ ! -f "$LOG_FILE" ]; then
    info "Creating log file $LOG_FILE"
    sudo touch "$LOG_FILE"
    sudo chown "$OWNER":"$OWNER" "$LOG_FILE"
    sudo chmod 644 "$LOG_FILE"
else
    info "Log file $LOG_FILE already exists, leaving permissions unchanged."
fi

# --------------------------------------------------------------------
# Step 3: Install script and credentials
# --------------------------------------------------------------------
info "Step 3: Installing noip-renew script to $INSTALL_DIR..."

# Determine source directory of this setup.sh (where noip-renew.py is)
SCRIPT_SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"

# Create install directory if needed
if [ ! -d "$INSTALL_DIR" ]; then
    info "Creating directory $INSTALL_DIR"
    sudo mkdir -p "$INSTALL_DIR"
    sudo chown "$OWNER":"$OWNER" "$INSTALL_DIR"
    sudo chmod 755 "$INSTALL_DIR"
else
    info "Install directory $INSTALL_DIR already exists."
fi

# Copy noip-renew.py (always overwrite)
if [ ! -f "$SCRIPT_SOURCE_DIR/noip-renew.py" ]; then
    error "noip-renew.py not found in $SCRIPT_SOURCE_DIR. Please run setup.sh from the directory containing noip-renew.py."
    exit 1
fi

info "Copying noip-renew.py to $INSTALL_DIR"
sudo cp "$SCRIPT_SOURCE_DIR/noip-renew.py" "$INSTALL_DIR/"
sudo chown "$OWNER":"$OWNER" "$INSTALL_DIR/noip-renew.py"
sudo chmod 755 "$INSTALL_DIR/noip-renew.py"

CRED_FILE="$INSTALL_DIR/credentials.txt"
CREATE_CREDS=0

if [ -f "$CRED_FILE" ]; then
    echo
    read -r -p "credentials.txt already exists in $INSTALL_DIR. Reuse it? [Y/n] " ans
    case "$ans" in
        [Nn]* )
            CREATE_CREDS=1
            ;;
        * )
            CREATE_CREDS=0
            info "Keeping existing credentials.txt."
            ;;
    esac
else
    CREATE_CREDS=1
fi

if [ "$CREATE_CREDS" -eq 1 ]; then
    echo
    info "Creating new credentials.txt in $INSTALL_DIR"
    read -r -p "No-IP username: " NOIP_USER
    read -rsp "No-IP password (will be base64-encoded, not stored in plain text): " NOIP_PASS
    echo
    read -r -p "No-IP TOTP secret key: " NOIP_TOTP

    NOIP_PASS_B64="$(printf '%s' "$NOIP_PASS" | base64)"

    tmpfile="$(mktemp)"
    cat > "$tmpfile" <<EOF
NOIP_USER=$NOIP_USER
NOIP_PASS_B64=$NOIP_PASS_B64
NOIP_TOTP_SECRET=$NOIP_TOTP
EOF

    sudo mv "$tmpfile" "$CRED_FILE"
    sudo chown "$OWNER":"$OWNER" "$CRED_FILE"
    sudo chmod 600 "$CRED_FILE"

    info "credentials.txt created and permissions set to 600."
fi

# --------------------------------------------------------------------
# Step 4: Add cron job with random time between 00:05 and 02:55
# --------------------------------------------------------------------
info "Step 4: Adding cron job..."

CRON_USER="$OWNER"

# Generate random time (single time, chosen now) in [00:05, 02:55]
# Range of minutes: 0:05 → 2*60+55 = 175 minutes total
# So offset 5..175 inclusive → 171 values
OFFSET=$((RANDOM % 171 + 5))
HOUR=$((OFFSET / 60))
MINUTE=$((OFFSET % 60))

CRON_LINE="$(printf '%d %d * * * /usr/bin/env python3 %s/noip-renew.py >> %s 2>&1' "$MINUTE" "$HOUR" "$INSTALL_DIR" "$LOG_FILE")"

# Choose correct crontab command depending on sudo usage
if [ -n "${SUDO_USER:-}" ]; then
    CRONCMD=(sudo crontab -u "$CRON_USER")
else
    CRONCMD=(crontab)
fi

EXISTING_CRON="$("${CRONCMD[@]}" -l 2>/dev/null || true)"

if echo "$EXISTING_CRON" | grep -Fq "$INSTALL_DIR/noip-renew.py"; then
    warn "A cron job for noip-renew.py already exists. Not adding another one."
else
    {
        printf "%s\n" "$EXISTING_CRON"
        printf "%s\n" "$CRON_LINE"
    } | "${CRONCMD[@]}" -
    info "Cron job installed for user $CRON_USER."
    printf '[INFO] Script has been scheduled to run daily at %02d:%02d.\n' "$HOUR" "$MINUTE"
    echo "[INFO] This time was chosen randomly once within the 00:05–02:55 window during setup."
fi

echo
info "Setup complete."

echo
info "Starting the script manually for initial run..."
python3 /usr/local/sbin/noip-renew/noip-renew.py

echo
info "Initial run finished. Future runs will follow the daily cron schedule."
