#!/usr/bin/env bash
# build.sh — Build mach_fuzzer and webkit_ipc_target
# Target: macOS 15.x, arm64 (Apple Silicon)
# Requires: Xcode Command Line Tools

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

SDK="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null)"
ARCH="arm64"
MIN_VER="15.0"

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
info()  { printf '  %-30s ' "$1"; }
ok()    { printf '\033[32m%s\033[0m\n' "ok"; }
fail()  { printf '\033[31mFAILED\033[0m\n'; exit 1; }

bold "==> Building Mach IPC Fuzzer (macOS ${MIN_VER}, ${ARCH})"
echo

# ── 1. mach_fuzzer ─────────────────────────────────────────────────────────
info "mach_fuzzer (pure C)"
clang \
    -O1 -g \
    -Wall -Wextra -Wno-unused-parameter \
    -arch "${ARCH}" \
    -mmacosx-version-min="${MIN_VER}" \
    -isysroot "${SDK}" \
    -o mach_fuzzer \
    mach_fuzzer.c \
    && ok || fail

# ── 2. webkit_ipc_target ───────────────────────────────────────────────────
info "webkit_ipc_target (ObjC++)"
clang++ \
    -ObjC++ -std=c++17 \
    -O1 -g \
    -Wall -Wextra -Wno-unused-parameter \
    -arch "${ARCH}" \
    -mmacosx-version-min="${MIN_VER}" \
    -isysroot "${SDK}" \
    -framework WebKit \
    -framework AppKit \
    -framework Foundation \
    -o webkit_ipc_target \
    webkit_ipc_target.mm \
    && ok || fail

# ── 3. findings directory ──────────────────────────────────────────────────
mkdir -p findings
info "findings/ directory"
ok

echo
bold "==> Build complete"
echo
echo "Quick start:"
echo "  ./mach_fuzzer --list-services"
echo "  ./mach_fuzzer --port com.apple.coreaudiod --mode random"
echo "  ./webkit_ipc_target --fuzz --mode mutate --out findings/"
echo "  ./webkit_ipc_target --find-port   # then pipe to mach_fuzzer --port-right"
echo
