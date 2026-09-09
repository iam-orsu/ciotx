#!/bin/sh
# ciotx installer
# This script is served at https://DOMAIN_NAME/install.sh
# Generated at build time with DOMAIN_NAME injected.
#
# Usage: curl -fsSL https://DOMAIN_NAME/install.sh | sh

set -e

# DOMAIN_NAME is injected at server startup by the nginx container
CIOTX_API="https://DOMAIN_NAME"
CIOTX_VERSION="1.0.0"
INSTALL_DIR="/usr/local/bin"

echo ""
echo "  ciotx — Security Auditor"
echo "  Installing v${CIOTX_VERSION}..."
echo ""

# ── Detect OS & Architecture ──────────────────────────────────────
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)
        echo "[!] Unsupported architecture: $ARCH"
        echo "    Please visit https://ciotx.ai for manual installation."
        exit 1
        ;;
esac

case "$OS" in
    linux|darwin) ;;
    *)
        echo "[!] Unsupported OS: $OS"
        echo "    Windows users: download ciotx.exe from https://ciotx.ai/download"
        exit 1
        ;;
esac

BINARY_NAME="ciotx-${OS}-${ARCH}"
DOWNLOAD_URL="${CIOTX_API}/releases/${CIOTX_VERSION}/${BINARY_NAME}.tar.gz"

echo "  Platform  : ${OS}/${ARCH}"
echo "  Downloading from ciotx servers..."

# ── Download & Install ────────────────────────────────────────────
TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/ciotx.tar.gz" || {
    echo ""
    echo "[!] Download failed. Please check your connection or visit https://ciotx.ai"
    exit 1
}

tar -xzf "${TMP_DIR}/ciotx.tar.gz" -C "$TMP_DIR"

# Install to /usr/local/bin (use sudo if needed)
if [ -w "$INSTALL_DIR" ]; then
    mv "${TMP_DIR}/ciotx" "${INSTALL_DIR}/ciotx"
else
    sudo mv "${TMP_DIR}/ciotx" "${INSTALL_DIR}/ciotx"
fi

chmod +x "${INSTALL_DIR}/ciotx"

echo ""
echo "  [+] ciotx installed successfully!"
echo ""
echo "  Next steps:"
echo "    1. Run: ciotx auth login"
echo "    2. Scan your code: ciotx scan /path/to/your/repo"
echo ""
echo "  Get your license key at https://ciotx.ai"
echo ""
