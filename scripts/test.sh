#!/usr/bin/env bash
# Configure + build with tests enabled, then run the CTest suite.
#
#   scripts/test.sh [extra cmake configure args...]
#
# The presets carry AAV_BUILD_TESTS, so this is `cmake --preset $PRESET` plus
# `ctest --preset $PRESET` and nothing else.
#
# Env: PRESET (default: debug), CC, CXX.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require ctest
PRESET="${PRESET:-debug}"

"$AAV_ROOT/scripts/build.sh" "$@"

log "Test (preset $PRESET)"
cd "$AAV_ROOT"  # `ctest --preset` reads CMakePresets.json from the current dir.
ctest --preset "$PRESET"
