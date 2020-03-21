#!/usr/bin/env bash
# Configure + build with tests enabled, then run the unit + e2e CTest suites.
#
#   scripts/test.sh [extra cmake configure args...]
#
# The presets carry AAV_BUILD_TESTS, so this is `cmake --preset $PRESET` plus
# `ctest --preset $PRESET` and nothing else. That pair is exactly what the build
# workflow runs, which is what makes a red CI leg reproducible with one command.
#
# Env: PRESET (default: debug; `release` is the other one CI runs), CC, CXX.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require ctest
PRESET="${PRESET:-debug}"

"$AAV_ROOT/scripts/build.sh" "$@"

log "Test (preset $PRESET)"
cd "$AAV_ROOT"  # `ctest --preset` reads CMakePresets.json from the current dir.
ctest --preset "$PRESET"
