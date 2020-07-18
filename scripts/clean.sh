#!/usr/bin/env bash
# Remove build directories and generated sample data.
#
#   scripts/clean.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

cd "$AAV_ROOT"

# $AAV_BUILD_ROOT is overridable and this is an rm -rf, so the cases where a
# typo costs more than a rebuild are refused rather than trusted: an empty
# value (which would make the path "/"), a root or home directory, and any
# directory containing the checkout -- the last one is what an
# AAV_BUILD_ROOT=.. would expand to.
remove_root() {
  local dir="$1"
  case "$dir" in
    "" | "/" | "$HOME" | "$HOME/") die "refusing to rm -rf '$dir'" ;;
  esac
  case "$AAV_ROOT/" in
    "$dir"/*) die "refusing to rm -rf '$dir': it contains the checkout" ;;
  esac
  log "Removing $dir"
  rm -rf "$dir"
}

# Two roots, and usually the same directory: the CMake preset trees are anchored
# to the source directory while everything else follows $AAV_BUILD_ROOT, so an
# override leaves generated output in two places and a clean has to reach both.
remove_root "$AAV_BUILD_ROOT"
[ "$AAV_PRESET_ROOT" = "$AAV_BUILD_ROOT" ] || remove_root "$AAV_PRESET_ROOT"

log "Removing generated samples"
rm -f samples/sample.dex samples/sample.sig
# Output from a checkout built before the build root moved out of the tree.
rm -rf build android/build android/app/build android/app/.cxx android/.gradle
log "Clean."
