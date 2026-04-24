#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="${PROFILE:-release}"
TARGET="x86_64-pc-windows-gnu"

if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "error: x86_64-w64-mingw32-gcc not found"
    echo "install with: brew install mingw-w64"
    exit 1
fi

if ! rustup target list --installed | grep -q "${TARGET}"; then
    echo "installing rust target ${TARGET}..."
    rustup target add "${TARGET}"
fi

if [ "${PROFILE}" = "release" ]; then
    cargo build -p haunt-windows --release
else
    cargo build -p haunt-windows
fi

OUT="${SCRIPT_DIR}/target/${TARGET}/${PROFILE}/haunt.dll"
echo ""
echo "built: ${OUT}"
file "${OUT}" 2>/dev/null || true
