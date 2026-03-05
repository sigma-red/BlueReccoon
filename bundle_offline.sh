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

# 1. Download all wheels (including transitive deps) for Linux x86_64
echo "[*] Downloading wheels for all requirements..."
pip download \
    -r requirements.txt \
    --dest "${WHEELS_DIR}" \
    --platform manylinux2014_x86_64 \
    --platform manylinux_2_17_x86_64 \
    --platform linux_x86_64 \
    --python-version 3 \
    --only-binary=:all: \
    2>/dev/null || true

# Some packages may not have binary wheels — download source as fallback
echo "[*] Downloading source fallbacks for any missing packages..."
pip download \
    -r requirements.txt \
    --dest "${WHEELS_DIR}" \
    --no-binary=:none: \
    2>/dev/null || true

# Deduplicate — keep wheels over sdists when both exist
echo "[*] Deduplicating packages..."
cd "${WHEELS_DIR}"
for whl in *.whl; do
    [ -f "$whl" ] || continue
    pkg_name=$(echo "$whl" | sed 's/-[0-9].*//' | tr '[:upper:]' '[:lower:]' | tr '_' '-')
    for tar in ${pkg_name}-*.tar.gz ${pkg_name}-*.zip; do
        [ -f "$tar" ] && rm -f "$tar"
    done
done
cd - > /dev/null

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

# Create venv
echo "[*] Creating virtual environment..."
$PYTHON -m venv "${VENV_DIR}"
source "${VENV_DIR}/bin/activate"

# Upgrade pip from local wheel if available
PIP_WHL=$(ls "${WHEELS_DIR}"/pip-*.whl 2>/dev/null | head -1)
if [ -n "$PIP_WHL" ]; then
    pip install --no-index "$PIP_WHL" 2>/dev/null || true
fi

# Install all dependencies from local wheels
echo "[*] Installing dependencies from offline wheels..."
pip install --no-index --find-links "${WHEELS_DIR}" -r "${APP_DIR}/requirements.txt"

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
INSTALL_EOF
chmod +x "${BUNDLE_DIR}/install.sh"

# 4. Create a convenience run script
cat > "${BUNDLE_DIR}/run.sh" << 'RUN_EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="${SCRIPT_DIR}/app"
source "${APP_DIR}/venv/bin/activate"
cd "${APP_DIR}"
exec python app.py "$@"
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
