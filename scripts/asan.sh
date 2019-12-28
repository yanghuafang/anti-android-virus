#!/usr/bin/env bash
# Build + test under AddressSanitizer + UndefinedBehaviorSanitizer.
#
#   scripts/asan.sh [extra cmake configure args...]
#
# Everything this needs is in the asan presets: the sanitizer flags,
# AAV_BUILD_TESTS, and the UBSAN_OPTIONS the runtime needs to print a usable
# report. So `cmake --preset asan && ctest --preset asan` is this script, and a
# failure reproduces without reading this file.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require cmake
require ctest
cd "$AAV_ROOT"  # `cmake --preset` reads CMakePresets.json from the current dir.

log "Configure (asan preset)"
cmake --preset asan "$@"

log "Build"
cmake --build --preset asan -j

log "Test (ASan/UBSan)"
ctest --preset asan
