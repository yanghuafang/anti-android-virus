#!/usr/bin/env bash
# Build with coverage instrumentation, run the test suite, and report line +
# branch coverage for the engine sources (src/) via gcovr.
#
#   scripts/coverage.sh [--html]
#
# Env:
#   COVERAGE_FAIL_UNDER   fail if line coverage % is below this (default: 65)
#   CC, CXX               compilers (honoured by CMake)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require cmake
require ctest
command -v gcovr >/dev/null 2>&1 || die "gcovr not found. Install it with:
  macOS:  brew install gcovr
  Ubuntu: sudo apt install gcovr
or run scripts/install-deps-{macos,ubuntu}.sh."

# Flags live in the 'coverage' CMake preset, which builds into the build root.
BUILD_PATH="$AAV_PRESET_ROOT/coverage"
cd "$AAV_ROOT"  # `cmake --preset` reads CMakePresets.json from the current dir.

WANT_HTML=0
for a in "$@"; do
  [ "$a" = "--html" ] && WANT_HTML=1
done

log "Configure (coverage preset)"
cmake --preset coverage

log "Build"
cmake --build --preset coverage -j

log "Test"
ctest --preset coverage

# clang's gcov data must be read with 'llvm-cov gcov'; gcc's gcov works as-is.
GCOV_ARGS=()
if "${CXX:-c++}" --version 2>/dev/null | grep -qi clang; then
  if command -v llvm-cov >/dev/null 2>&1; then
    GCOV_ARGS+=(--gcov-executable "llvm-cov gcov")
  elif command -v xcrun >/dev/null 2>&1; then
    GCOV_ARGS+=(--gcov-executable "xcrun llvm-cov gcov")
  fi
fi

# The floor is the script's default, not something CI passes in: a threshold
# that only exists in a workflow file is one a developer cannot reproduce, and
# they find out it moved when the pull request goes red. Set it to 0 to report
# without gating.
FAIL_ARGS=(--fail-under-line "${COVERAGE_FAIL_UNDER:-65}")

HTML_ARGS=()
if [ "$WANT_HTML" = "1" ]; then
  mkdir -p "$BUILD_PATH/coverage_html"
  HTML_ARGS+=(--html --html-details -o "$BUILD_PATH/coverage_html/index.html")
  log "HTML report: $BUILD_PATH/coverage_html/index.html"
fi

log "Coverage (src/ only)"
# --gcov-ignore-parse-errors tolerates "branch N taken -1" from gcov (GCC
# PR68080); without it gcovr aborts the run. Line coverage is what matters, so
# warn once per file and continue. The ${a[@]+"${a[@]}"} form is what makes an
# empty array expand safely under `set -u` on bash 3.2 (macOS).
gcovr \
  --root "$AAV_ROOT" \
  --filter "$AAV_ROOT/src/" \
  --exclude-unreachable-branches \
  --gcov-ignore-parse-errors=negative_hits.warn_once_per_file \
  --print-summary \
  ${GCOV_ARGS[@]+"${GCOV_ARGS[@]}"} \
  ${FAIL_ARGS[@]+"${FAIL_ARGS[@]}"} \
  ${HTML_ARGS[@]+"${HTML_ARGS[@]}"} \
  "$BUILD_PATH"
