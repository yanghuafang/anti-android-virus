#!/usr/bin/env bash
# Build with coverage instrumentation, run the test suite, and report line +
# branch coverage for the engine sources (src/) via gcovr.
#
#   scripts/coverage.sh [--html]
#
# Env:
#   COVERAGE_FAIL_UNDER   fail if line coverage % is below this (default: none)
#   CC, CXX               compilers (honoured by CMake)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require cmake
require ctest
if ! command -v gcovr >/dev/null 2>&1; then
  die "gcovr not found. Install it with: pip install gcovr"
fi

# Flags live in the 'coverage' CMake preset (build/coverage).
BUILD_PATH="$AAV_ROOT/build/coverage"
cd "$AAV_ROOT"  # `cmake --preset` reads CMakePresets.json from the current dir.

WANT_HTML=0
for a in "$@"; do
  [ "$a" = "--html" ] && WANT_HTML=1
done

log "Configure (coverage preset)"
cmake --preset coverage

log "Build"
cmake --build "$BUILD_PATH" -j

log "Test"
ctest --test-dir "$BUILD_PATH" --output-on-failure

# clang emits gcov data that must be read with 'llvm-cov gcov'; gcc's gcov works
# out of the box. Point gcovr at the right tool.
GCOV_ARGS=()
if "${CXX:-c++}" --version 2>/dev/null | grep -qi clang; then
  if command -v llvm-cov >/dev/null 2>&1; then
    GCOV_ARGS+=(--gcov-executable "llvm-cov gcov")
  elif command -v xcrun >/dev/null 2>&1; then
    GCOV_ARGS+=(--gcov-executable "xcrun llvm-cov gcov")
  fi
fi

FAIL_ARGS=()
if [ -n "${COVERAGE_FAIL_UNDER:-}" ]; then
  FAIL_ARGS+=(--fail-under-line "$COVERAGE_FAIL_UNDER")
fi

HTML_ARGS=()
if [ "$WANT_HTML" = "1" ]; then
  mkdir -p "$BUILD_PATH/coverage_html"
  HTML_ARGS+=(--html --html-details -o "$BUILD_PATH/coverage_html/index.html")
  log "HTML report: $BUILD_PATH/coverage_html/index.html"
fi

log "Coverage (src/ only)"
# --gcov-ignore-parse-errors tolerates gcov emitting "branch N taken -1"
# (negative hit counts), a known GCC gcov bug (gcc.gnu.org PR68080); without it
# gcovr aborts the whole run. We only care about line coverage, so warn (once
# per file) and keep going.
# Guard empty-array expansion so the script works under `set -u` on bash 3.2.
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
