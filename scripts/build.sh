#!/usr/bin/env bash
# Configure + build the engine, the aavscan CLI, and sigtool on the host.
#
#   scripts/build.sh [extra cmake configure args...]
#
# Env:
#   BUILD_TYPE  CMake build type (default: Debug)
#   BUILD_DIR   output directory (default: build/host)
#   CC, CXX     compilers (honoured by CMake)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require cmake
BUILD_TYPE="${BUILD_TYPE:-Debug}"
BUILD_DIR="${BUILD_DIR:-build/host}"

log "Configure  type=$BUILD_TYPE  dir=$BUILD_DIR${CXX:+  CXX=$CXX}"
cmake -S "$AAV_ROOT" -B "$AAV_ROOT/$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
  -DAAV_BUILD_TESTS=ON \
  "$@"

log "Build"
cmake --build "$AAV_ROOT/$BUILD_DIR" -j

log "Done. Binaries: $BUILD_DIR/bin (aavscan, sigtool)   library: $BUILD_DIR/lib/libaav.a"
