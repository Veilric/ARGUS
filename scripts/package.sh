#!/usr/bin/env bash
# ==============================================================================
# ARGUS by Veilric — Reproducible Safe Release Packaging Script
# Bundles clean, zero-leak release archive excluding all developer Git history,
# local baselines, runtime logs, generated reports, and temporary files.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION="1.1.0"
PACKAGE_NAME="ARGUS-v${VERSION}"
RELEASE_ZIP="${PROJECT_ROOT}/dist/${PACKAGE_NAME}.zip"

export PATH="${HOME}/.local/go/bin:${HOME}/go/bin:${PATH}"

cd "${PROJECT_ROOT}"

echo "===================================================================="
echo "  ARGUS by Veilric — Release Packaging (v${VERSION})"
echo "===================================================================="

# Step 1: Ensure static binaries are built
echo "[1/4] Ensuring binaries are compiled..."
"${SCRIPT_DIR}/build.sh"

# Step 2: Create isolated staging tree
echo "[2/4] Assembling clean release staging tree..."
TMP_DIR="$(mktemp -d /tmp/argus_package_XXXXXX)"
cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

STAGE_DIR="${TMP_DIR}/${PACKAGE_NAME}"
mkdir -p "${STAGE_DIR}"

# Copy source code and build configs
cp -r "${PROJECT_ROOT}/cmd" "${STAGE_DIR}/"
cp -r "${PROJECT_ROOT}/internal" "${STAGE_DIR}/"
cp -r "${PROJECT_ROOT}/scripts" "${STAGE_DIR}/"
if [ -d "${PROJECT_ROOT}/examples" ]; then
    cp -r "${PROJECT_ROOT}/examples" "${STAGE_DIR}/"
fi
cp "${PROJECT_ROOT}/go.mod" "${STAGE_DIR}/"
cp "${PROJECT_ROOT}/go.sum" "${STAGE_DIR}/"
cp "${PROJECT_ROOT}/README.md" "${STAGE_DIR}/"
if [ -f "${PROJECT_ROOT}/LICENSE" ]; then
    cp "${PROJECT_ROOT}/LICENSE" "${STAGE_DIR}/"
fi
cp "${PROJECT_ROOT}/.gitignore" "${STAGE_DIR}/"

# Copy pre-compiled release binaries
mkdir -p "${STAGE_DIR}/dist"
cp "${PROJECT_ROOT}/dist/argus" "${STAGE_DIR}/dist/"
cp "${PROJECT_ROOT}/dist/argus.exe" "${STAGE_DIR}/dist/"
cp "${PROJECT_ROOT}/dist/argus" "${STAGE_DIR}/argus"
cp "${PROJECT_ROOT}/dist/argus.exe" "${STAGE_DIR}/argus.exe"

# Copy pristine skeleton directories with .gitkeep ONLY
mkdir -p "${STAGE_DIR}/config"
touch "${STAGE_DIR}/config/.gitkeep"
mkdir -p "${STAGE_DIR}/logs"
touch "${STAGE_DIR}/logs/.gitkeep"
mkdir -p "${STAGE_DIR}/reports"
touch "${STAGE_DIR}/reports/.gitkeep"

# Step 3: Audit staging tree for prohibited files
echo "[3/4] Running pre-packaging security audit on staging tree..."

PROHIBITED_FILES=(
    ".git"
    "baselines.json"
    "baselines.json.bak"
    "*.bak"
    "*.tmp"
    "*.swp"
    "*~"
    "reports/*.md"
    "reports/*.json"
    "logs/*.log"
)

# Search for prohibited files in staging tree
find "${STAGE_DIR}" -name ".git" -exec echo "VIOLATION: Found .git directory: {}" \; -exec false {} +
find "${STAGE_DIR}" -name "*.bak" -exec echo "VIOLATION: Found backup file: {}" \; -exec false {} +
find "${STAGE_DIR}" -name "*.tmp" -exec echo "VIOLATION: Found temp file: {}" \; -exec false {} +
find "${STAGE_DIR}" -name "baselines.json" -exec echo "VIOLATION: Found baseline file: {}" \; -exec false {} +
find "${STAGE_DIR}/reports" -type f ! -name ".gitkeep" -exec echo "VIOLATION: Found report in reports/: {}" \; -exec false {} +
find "${STAGE_DIR}/logs" -type f ! -name ".gitkeep" -exec echo "VIOLATION: Found log in logs/: {}" \; -exec false {} +

# Step 4: Create and verify ZIP archive
echo "[4/4] Creating and verifying ZIP archive: ${RELEASE_ZIP}..."
mkdir -p "${PROJECT_ROOT}/dist"
rm -f "${RELEASE_ZIP}"

cd "${TMP_DIR}"
zip -q -r "${RELEASE_ZIP}" "${PACKAGE_NAME}"

# Post-packaging ZIP table of contents audit
echo "Auditing ZIP table of contents..."
ZIP_CONTENTS="$(unzip -l "${RELEASE_ZIP}")"

# Verify prohibited entries do not exist in ZIP
check_prohibited() {
    local pattern="$1"
    if echo "${ZIP_CONTENTS}" | grep -E "${pattern}" > /dev/null; then
        echo "SECURITY ERROR: Prohibited file matching pattern '${pattern}' found in release ZIP!"
        rm -f "${RELEASE_ZIP}"
        exit 1
    fi
}

check_prohibited '\.git/'
check_prohibited '\.git$'
check_prohibited 'baselines\.json'
check_prohibited '\.bak$'
check_prohibited '\.tmp$'
check_prohibited 'reports/.*\.md$'
check_prohibited 'reports/.*\.json$'
check_prohibited 'logs/.*\.log$'

# Verify essential files are present
check_required() {
    local pattern="$1"
    if ! echo "${ZIP_CONTENTS}" | grep -E "${pattern}" > /dev/null; then
        echo "ERROR: Essential file matching pattern '${pattern}' missing from release ZIP!"
        rm -f "${RELEASE_ZIP}"
        exit 1
    fi
}

check_required "${PACKAGE_NAME}/argus$"
check_required "${PACKAGE_NAME}/argus\.exe$"
check_required "${PACKAGE_NAME}/README\.md$"
check_required "${PACKAGE_NAME}/LICENSE$"
check_required "${PACKAGE_NAME}/go\.mod$"
check_required "${PACKAGE_NAME}/config/\.gitkeep$"

echo ""
echo "===================================================================="
echo "[✔] Release package successfully created and verified!"
echo "    File: ${RELEASE_ZIP}"
echo "    Size: $(ls -lh "${RELEASE_ZIP}" | awk '{print $5}')"
echo "===================================================================="
