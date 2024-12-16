#!/usr/bin/env bash
# Install the full aav build/test toolchain on Debian/Ubuntu (24.04 / 26.04).
#
# Covers everything CI does: the core build (gcc/g++, cmake, zlib) plus the
# clang matrix, clang-format (format check), and gcovr (coverage). libFuzzer
# ships with the distro clang, so no extra package is needed for the fuzzer.
#
# The Android NDK is NOT installed here (it comes via Android Studio or
# `sdkmanager "ndk;<version>"`); see docs/Building.md.
#
#   scripts/install-deps-ubuntu.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require apt-get

# Use sudo only when not already root and it is available (CI runners need it;
# root containers do not have/where-need sudo).
SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
fi

log "Installing aav build/test dependencies (apt)"
$SUDO apt-get update
$SUDO apt-get install -y \
  build-essential \
  cmake \
  zlib1g-dev \
  clang \
  clang-format \
  gcovr

log "Done: gcc/g++ + cmake + zlib (build), clang + libFuzzer (clang matrix /"
log "fuzz), clang-format (format), gcovr (coverage). Android NDK is separate."
