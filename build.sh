#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="${PROFILE:-release}"
# ARCH selects the Windows architecture of the produced haunt.dll.
# x86_64 = 64-bit (default), i686 = 32-bit (for 32-bit target processes like MHOClient).
ARCH="${ARCH:-x86_64}"

case "${ARCH}" in
    x86_64) TARGET="x86_64-pc-windows-gnu"; MINGW_GCC="x86_64-w64-mingw32-gcc" ;;
    i686)   TARGET="i686-pc-windows-gnu";   MINGW_GCC="i686-w64-mingw32-gcc"   ;;
    *)      echo "error: unknown ARCH=${ARCH} (expected x86_64 or i686)"; exit 1 ;;
esac

if ! command -v "${MINGW_GCC}" >/dev/null 2>&1; then
    echo "error: ${MINGW_GCC} not found"
    echo "install with: brew install mingw-w64"
    exit 1
fi

if ! rustup target list --installed | grep -q "${TARGET}"; then
    echo "installing rust target ${TARGET}..."
    rustup target add "${TARGET}"
fi

if [ "${PROFILE}" = "release" ]; then
    cargo build -p haunt-windows --release --target "${TARGET}"
else
    cargo build -p haunt-windows --target "${TARGET}"
fi

OUT="${SCRIPT_DIR}/target/${TARGET}/${PROFILE}/haunt.dll"
echo ""
echo "built: ${OUT}"
file "${OUT}" 2>/dev/null || true
