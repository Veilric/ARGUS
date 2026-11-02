#!/usr/bin/env bash
# ==============================================================================
# ARGUS by Veilric — Cross-Platform Static Build Script
# Compiles zero-dependency standalone binaries for Linux and Windows
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

export PATH="${HOME}/.local/go/bin:${HOME}/go/bin:${PATH}"

cd "${PROJECT_ROOT}"

echo "===================================================================="
echo "  Building ARGUS by Veilric (Static Portable Binaries)"
echo "===================================================================="

# Clean previous build artifacts
mkdir -p dist

echo "[1/2] Compiling Linux static binary (x86_64 ELF)..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=1.0.0" \
    -o dist/argus cmd/argus/main.go

echo "[2/2] Cross-compiling Windows standalone executable (x86_64 PE)..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=1.0.0" \
    -o dist/argus.exe cmd/argus/main.go

# Copy binaries to root for immediate USB root access
cp dist/argus ./argus
cp dist/argus.exe ./argus.exe

chmod +x dist/argus ./argus

echo ""
echo "[✔] Build Complete!"
ls -lh dist/
echo ""
echo "Files ready in ./dist and ./ ready to copy to a USB flash drive."
