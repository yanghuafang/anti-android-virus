#!/usr/bin/env bash
# Configure + build the engine, the aavscan CLI, and sigtool on the host.
#
#   scripts/build.sh [extra cmake configure args...]
#
# A wrapper around `cmake --preset "$PRESET"`, not a second way to configure the
# project: CI runs the same presets, so a build here and a build there differ
# only in the machine. Anything the presets do not express still passes through
# as a configure argument, e.g.
#   scripts/build.sh -DCMAKE_BUILD_TYPE=RelWithDebInfo
#
# Env:
#   PRESET      configure/build preset (default: debug; see `cmake --list-presets`)
#   CC, CXX     compilers (honoured by CMake)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require cmake
PRESET="${PRESET:-debug}"
cd "$AAV_ROOT"  # `cmake --preset` reads CMakePresets.json from the current dir.

log "Configure  preset=$PRESET${CXX:+  CXX=$CXX}"
cmake --preset "$PRESET" "$@"

log "Build"
cmake --build --preset "$PRESET" -j

BUILD_DIR="$AAV_PRESET_ROOT/$PRESET"
log "Done. Binaries: $BUILD_DIR/bin (aavscan, sigtool)   library: $BUILD_DIR/lib/libaav.a"
