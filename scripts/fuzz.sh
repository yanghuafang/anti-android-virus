#!/usr/bin/env bash
# Build the libFuzzer DEX harness and run it.
#
# Requires a Clang with the libFuzzer + sanitizer runtimes:
#   - Linux: the distro clang (CC=clang CXX=clang++)
#   - macOS: Homebrew LLVM, e.g.
#       CC="$(brew --prefix llvm)/bin/clang" CXX="$(brew --prefix llvm)/bin/clang++" scripts/fuzz.sh
#
#   scripts/fuzz.sh [extra libFuzzer args...]
#
# Env: FUZZ_TIME seconds (default: 30)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require cmake
FUZZ_TIME="${FUZZ_TIME:-30}"
# Flags live in the 'fuzz' CMake preset (build/fuzz).
BUILD_PATH="$AAV_ROOT/build/fuzz"
cd "$AAV_ROOT"  # `cmake --preset` reads CMakePresets.json from the current dir.

log "Configure (fuzz preset)"
cmake --preset fuzz

log "Build fuzz_dexfile"
cmake --build "$BUILD_PATH" --target fuzz_dexfile -j

log "Run (max_total_time=${FUZZ_TIME}s)"
"$BUILD_PATH/bin/fuzz_dexfile" -max_total_time="$FUZZ_TIME" "$@"
