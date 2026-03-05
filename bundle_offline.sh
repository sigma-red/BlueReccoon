#!/bin/bash
# ============================================================================
# BlueReccoon Offline Bundle Script
# ============================================================================
# Run this on a machine WITH internet to download all dependencies as wheels,
# then transfer the resulting tarball to the air-gapped host.
#
# Usage (internet-connected machine):
#   chmod +x bundle_offline.sh
#   ./bundle_offline.sh
#
# Transfer the resulting bluereccoon-offline.tar.gz to the target host, then:
#   tar xzf bluereccoon-offline.tar.gz
#   cd bluereccoon-offline
#   ./install.sh
# ============================================================================

set -e

BUNDLE_DIR="bluereccoon-offline"
WHEELS_DIR="${BUNDLE_DIR}/wheels"
ARCHIVE="bluereccoon-offline.tar.gz"

echo "[*] BlueReccoon Offline Bundler"
echo "================================"

# Clean previous bundle
rm -rf "${BUNDLE_DIR}" "${ARCHIVE}"
mkdir -p "${WHEELS_DIR}"

# 1. Download pip/setuptools wheels (needed to bootstrap on air-gapped host)
echo "[*] Downloading pip and setuptools wheels..."
pip3 download pip setuptools wheel --dest "${WHEELS_DIR}" || true

# 2. Download ALL pinned dependencies (requirements-lock.txt has every
#    transitive dep explicitly listed — no resolver surprises on target)
LOCK_FILE="requirements-lock.txt"
if [ ! -f "$LOCK_FILE" ]; then
    echo "[!] requirements-lock.txt not found — generating from requirements.txt..."
    TMPVENV=$(mktemp -d)
    python3 -m venv "${TMPVENV}" 2>/dev/null \
        || python3 -m venv --without-pip "${TMPVENV}" 2>/dev/null

    # Bootstrap pip in temp venv
    TVPIP="${TMPVENV}/bin/pip"
    if [ ! -x "$TVPIP" ]; then
        PIP_BOOTSTRAP=$(ls "${WHEELS_DIR}"/pip-*.whl 2>/dev/null | head -1)
        "${TMPVENV}/bin/python" -c "
import sys, zipfile, tempfile
with zipfile.ZipFile('${PIP_BOOTSTRAP}') as z:
    td = tempfile.mkdtemp(); z.extractall(td)
sys.path.insert(0, td)
from pip._internal.cli.main import main
sys.exit(main(['install', '--no-index', '${PIP_BOOTSTRAP}']))
"
    fi

    "${TMPVENV}/bin/pip" install -r requirements.txt > /dev/null 2>&1
    "${TMPVENV}/bin/pip" freeze > "$LOCK_FILE"
    rm -rf "${TMPVENV}"
    echo "[+] Generated $LOCK_FILE with $(wc -l < "$LOCK_FILE") pinned packages"
fi

echo "[*] Downloading all wheels from lock file..."
pip3 download -r "$LOCK_FILE" --dest "${WHEELS_DIR}"

# Verify: check every pinned package has a matching file in the wheels dir
echo "[*] Verifying all packages were downloaded..."
MISSING=0
while IFS= read -r line; do
    # Skip comments and blank lines
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    pkg=$(echo "$line" | sed 's/[>=<].*//' | tr '[:upper:]' '[:lower:]' | tr '-' '_')
    if ! ls "${WHEELS_DIR}"/ 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr '-' '_' | grep -qi "^${pkg}"; then
        echo "    [!] MISSING: $line"
        MISSING=$((MISSING + 1))
    fi
done < "$LOCK_FILE"

if [ "$MISSING" -gt 0 ]; then
    echo "[!] WARNING: $MISSING package(s) missing from wheels dir"
    echo "    The air-gapped install may fail. Check errors above."
else
    echo "[+] All $(grep -v '^#' "$LOCK_FILE" | grep -v '^$' | wc -l) packages verified in wheels dir"
fi

echo "[*] Downloaded $(ls -1 "${WHEELS_DIR}" | wc -l) files total"

# 2. Copy the application code
echo "[*] Copying BlueReccoon application..."
rsync -a --exclude="${BUNDLE_DIR}" \
         --exclude=".git" \
         --exclude="__pycache__" \
         --exclude="*.pyc" \
         --exclude="*.db" \
         --exclude="${ARCHIVE}" \
         . "${BUNDLE_DIR}/app/"

# 3. Create the install script for the air-gapped host
cat > "${BUNDLE_DIR}/install.sh" << 'INSTALL_EOF'
#!/bin/bash
# ============================================================================
# BlueReccoon Offline Installer — run on the air-gapped host
# ============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="${SCRIPT_DIR}/app"
WHEELS_DIR="${SCRIPT_DIR}/wheels"
VENV_DIR="${APP_DIR}/venv"

echo "[*] BlueReccoon Offline Installer"
echo "==================================="

# Check Python
PYTHON=""
for py in python3.12 python3.11 python3.10 python3.9 python3; do
    if command -v "$py" &>/dev/null; then
        PYTHON="$py"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "[!] Python 3 not found. Install python3 first."
    exit 1
fi

echo "[*] Using: $($PYTHON --version)"

USE_VENV=0
INSTALL_MODE=""

# Try creating venv — handle missing python3-venv package (common on Debian/Kali)
echo "[*] Setting up Python environment..."
if $PYTHON -m venv "${VENV_DIR}" > /dev/null 2>&1; then
    echo "[+] venv created successfully"
    source "${VENV_DIR}/bin/activate"
    USE_VENV=1
    INSTALL_MODE="venv"
else
    # Clean up any partial venv left behind
    rm -rf "${VENV_DIR}"

    # Try --without-pip (still needs the venv module to exist)
    if $PYTHON -m venv --without-pip "${VENV_DIR}" > /dev/null 2>&1; then
        echo "[+] venv created (without pip — will bootstrap from wheel)"
        source "${VENV_DIR}/bin/activate"
        USE_VENV=1
        INSTALL_MODE="venv-no-pip"
    else
        rm -rf "${VENV_DIR}"
        echo "[!] python3-venv not available — installing to user site-packages"
        INSTALL_MODE="user"
    fi
fi

# Locate the bundled pip wheel (needed for bootstrap and --user installs)
PIP_WHL=$(ls "${WHEELS_DIR}"/pip-*.whl 2>/dev/null | head -1)
if [ -z "$PIP_WHL" ]; then
    echo "[!] ERROR: No pip wheel found in ${WHEELS_DIR}/"
    echo "    Re-run bundle_offline.sh on an internet-connected machine."
    exit 1
fi

# Helper: run pip directly from the wheel zip (works without pip installed)
run_pip_from_wheel() {
    $PYTHON -c "
import sys, zipfile, tempfile, os
whl = '$PIP_WHL'
td = tempfile.mkdtemp()
with zipfile.ZipFile(whl) as z:
    z.extractall(td)
sys.path.insert(0, td)
from pip._internal.cli.main import main
sys.exit(main(sys.argv[1:]))
" "$@"
}

if [ "$USE_VENV" -eq 1 ]; then
    # Install deps into the venv — use run_pip_from_wheel for all cases
    # since pip may not be installed in the venv itself (--without-pip path)
    # Use lock file (every dep pinned) if available, else fall back to requirements.txt
    REQ_FILE="${APP_DIR}/requirements-lock.txt"
    [ ! -f "$REQ_FILE" ] && REQ_FILE="${APP_DIR}/requirements.txt"
    echo "[*] Installing dependencies from offline wheels..."
    echo "    Using: $(basename "$REQ_FILE")"
    run_pip_from_wheel install --no-index --find-links "${WHEELS_DIR}" -r "${REQ_FILE}"

    echo ""
    echo "[+] Installation complete!"
    echo ""
    echo "To run BlueReccoon:"
    echo "  cd ${APP_DIR}"
    echo "  source venv/bin/activate"
    echo "  python app.py"
    echo ""
    echo "Or use the run script:"
    echo "  ${SCRIPT_DIR}/run.sh"
else
    # No venv at all — install to ~/.local via --user
    REQ_FILE="${APP_DIR}/requirements-lock.txt"
    [ ! -f "$REQ_FILE" ] && REQ_FILE="${APP_DIR}/requirements.txt"
    echo "[*] Installing dependencies to user site-packages..."
    echo "    Using: $(basename "$REQ_FILE")"
    run_pip_from_wheel install --user --no-index \
        --find-links "${WHEELS_DIR}" -r "${REQ_FILE}"

    echo ""
    echo "[+] Installation complete! (installed to ~/.local/lib/python3/)"
    echo ""
    echo "To run BlueReccoon:"
    echo "  cd ${APP_DIR}"
    echo "  $PYTHON app.py"
fi
INSTALL_EOF
chmod +x "${BUNDLE_DIR}/install.sh"

# 4. Create a convenience run script
cat > "${BUNDLE_DIR}/run.sh" << 'RUN_EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="${SCRIPT_DIR}/app"
if [ -f "${APP_DIR}/venv/bin/activate" ]; then
    source "${APP_DIR}/venv/bin/activate"
fi
cd "${APP_DIR}"
exec python3 app.py "$@"
RUN_EOF
chmod +x "${BUNDLE_DIR}/run.sh"

# 5. Package everything
echo "[*] Creating archive: ${ARCHIVE}"
tar czf "${ARCHIVE}" "${BUNDLE_DIR}"

SIZE=$(du -sh "${ARCHIVE}" | cut -f1)
WHEEL_COUNT=$(ls -1 "${WHEELS_DIR}" | wc -l)

echo ""
echo "[+] Bundle complete!"
echo "    Archive:  ${ARCHIVE} (${SIZE})"
echo "    Wheels:   ${WHEEL_COUNT} packages"
echo ""
echo "Transfer ${ARCHIVE} to the air-gapped host, then:"
echo "    tar xzf ${ARCHIVE}"
echo "    cd ${BUNDLE_DIR}"
echo "    ./install.sh"
