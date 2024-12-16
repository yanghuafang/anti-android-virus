#!/usr/bin/env bash
# Install the full aav build/test toolchain on macOS (Homebrew).
#
# The base compiler (Apple Clang) and zlib come with the Xcode Command Line
# Tools -- run `xcode-select --install` first if you don't have them. This adds:
#   cmake         - build system
#   llvm          - its clang++ ships the libFuzzer runtime Apple Clang lacks
#   clang-format  - format check
#   gcovr         - coverage report
#
# The Android NDK is NOT installed here (it comes via Android Studio); see
# docs/Building.md.
#
#   scripts/install-deps-macos.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require brew

log "Installing aav build/test dependencies (brew)"
brew install cmake llvm gcovr clang-format

log "Done. To build the fuzzer, point CC/CXX at Homebrew LLVM, e.g.:"
log "  CC=\"\$(brew --prefix llvm)/bin/clang\" \\"
log "  CXX=\"\$(brew --prefix llvm)/bin/clang++\" scripts/fuzz.sh"
