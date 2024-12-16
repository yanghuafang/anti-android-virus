#!/usr/bin/env bash
# End-to-end demo: build the CLI + tooling (if needed), synthesize a sample DEX
# and matching signature DB with sigtool, then scan with aavscan.
#
#   scripts/run.sh [file-or-dir]
#     no argument  -> scan the generated sample.dex
#     file/dir     -> scan your own .dex/.apk (or a directory) with the sample DB
#
# Env: BUILD_DIR (default: build/host), SAMPLES_DIR (default: <repo>/samples)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

BUILD_DIR="${BUILD_DIR:-build/host}"
BIN="$AAV_ROOT/$BUILD_DIR/bin"
SAMPLES="${SAMPLES_DIR:-$AAV_ROOT/samples}"

if [ ! -x "$BIN/aavscan" ] || [ ! -x "$BIN/sigtool" ]; then
  log "aavscan/sigtool not built yet — building"
  BUILD_DIR="$BUILD_DIR" "$AAV_ROOT/scripts/build.sh"
fi

mkdir -p "$SAMPLES"
if [ ! -f "$SAMPLES/sample.sig" ] || [ ! -f "$SAMPLES/sample.dex" ]; then
  log "Generating sample DEX + signature DB -> $SAMPLES"
  "$BIN/sigtool" gen-sample "$SAMPLES"
fi

TARGET="${1:-$SAMPLES/sample.dex}"
log "Scanning: $TARGET"
"$BIN/aavscan" "$SAMPLES/sample.sig" "$TARGET"
