#!/usr/bin/env bash
# Build the libFuzzer DEX harness and run it.
#
#   scripts/fuzz.sh                 build, then fuzz for $FUZZ_TIME seconds
#   scripts/fuzz.sh --build-only    build only; no run
#   scripts/fuzz.sh [libFuzzer args...]
#
# --build-only exists for CI, where the two halves are graded differently: the
# build is a gate (a harness that stops compiling against the engine API is a
# real break), while a seedless run explores different input every time, so
# failing a pull request on it would fail it for a finding it did not introduce.
# Splitting them here rather than in the workflow keeps both halves reproducible
# with one command.
#
# Requires a Clang with the libFuzzer + sanitizer runtimes:
#   - Linux: the distro clang (CC=clang CXX=clang++)
#   - macOS: Homebrew LLVM, e.g.
#       CC="$(brew --prefix llvm@18)/bin/clang" \
#       CXX="$(brew --prefix llvm@18)/bin/clang++" scripts/fuzz.sh
#
# Env: FUZZ_TIME seconds (default: 30)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require cmake
FUZZ_TIME="${FUZZ_TIME:-30}"
# Flags live in the 'fuzz' CMake preset, which builds into the build root.
BUILD_PATH="$AAV_PRESET_ROOT/fuzz"

BUILD_ONLY=0
if [ "${1:-}" = "--build-only" ]; then
  BUILD_ONLY=1
  shift
fi

cd "$AAV_ROOT"  # `cmake --preset` reads CMakePresets.json from the current dir.

log "Configure (fuzz preset)"
cmake --preset fuzz

log "Build fuzz_dexfile"
cmake --build --preset fuzz --target fuzz_dexfile -j

if [ "$BUILD_ONLY" = "1" ]; then
  log "Built $BUILD_PATH/bin/fuzz_dexfile (--build-only; not running)."
  exit 0
fi

# libFuzzer writes a crashing input to the working directory and names it after
# its hash, which on a CI runner means the one artifact worth keeping is the one
# thrown away with the machine. Send them somewhere nameable instead; the
# trailing slash is what makes libFuzzer treat this as a directory.
ARTIFACTS="$BUILD_PATH/artifacts"
mkdir -p "$ARTIFACTS"

log "Run (max_total_time=${FUZZ_TIME}s, artifacts -> $ARTIFACTS)"
"$BUILD_PATH/bin/fuzz_dexfile" \
  -max_total_time="$FUZZ_TIME" \
  -artifact_prefix="$ARTIFACTS/" \
  "$@"
