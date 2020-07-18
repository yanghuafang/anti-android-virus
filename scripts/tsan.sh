#!/usr/bin/env bash
# Build + test under ThreadSanitizer.
#
#   scripts/tsan.sh [extra cmake configure args...]
#
# What this covers that scripts/asan.sh cannot: the scan thread pool in
# src/engine/engine.cc and the mutex serializing Emit(). ASan and TSan cannot be
# linked into one binary, so this is a separate build tree and a separate CI job
# rather than another flag on the asan preset.
#
# A race aborts rather than prints, via TSAN_OPTIONS=halt_on_error=1 in the tsan
# test preset -- TSan is not covered by -fno-sanitize-recover=all, so without it
# ctest reports a pass over a log full of real races.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require cmake
require ctest
cd "$AAV_ROOT"  # `cmake --preset` reads CMakePresets.json from the current dir.

log "Configure (tsan preset)"
cmake --preset tsan "$@"

log "Build"
cmake --build --preset tsan -j

log "Test (TSan)"
ctest --preset tsan
