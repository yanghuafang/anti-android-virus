#!/usr/bin/env bash
# Configure + build with tests enabled, then run the unit + e2e CTest suites.
#
#   scripts/test.sh [extra cmake configure args...]
#
# Env: BUILD_DIR (default: build/host); also honours BUILD_TYPE / CC / CXX.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require ctest
BUILD_DIR="${BUILD_DIR:-build/host}"

BUILD_DIR="$BUILD_DIR" "$AAV_ROOT/scripts/build.sh" "$@"

log "Test"
ctest --test-dir "$AAV_ROOT/$BUILD_DIR" --output-on-failure
