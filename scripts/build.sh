#!/usr/bin/env bash
# Configure + build the engine on the host.
#
#   scripts/build.sh [extra cmake configure args...]
#
# A wrapper around `cmake --preset "$PRESET"`, not a second way to configure the
# project, so a build here and a build anywhere else differ only in the machine.
# Anything the presets do not express still passes through as a configure
# argument, e.g.
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

log "Done. Library: $AAV_BUILD_ROOT/$PRESET/lib/libaav.a"
