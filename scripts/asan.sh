#!/usr/bin/env bash
# Build + test under AddressSanitizer + UndefinedBehaviorSanitizer (asan preset).
#
#   scripts/asan.sh [extra cmake configure args...]
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require cmake
require ctest
cd "$AAV_ROOT"  # `cmake --preset` reads CMakePresets.json from the current dir.

log "Configure (asan preset)"
cmake --preset asan -DAAV_BUILD_TESTS=ON "$@"

log "Build"
cmake --build "$AAV_ROOT/build/asan" -j

log "Test (ASan/UBSan)"
ctest --test-dir "$AAV_ROOT/build/asan" --output-on-failure
