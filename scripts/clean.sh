#!/usr/bin/env bash
# Remove build directories.
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

remove_root "$AAV_BUILD_ROOT"
# Output from a checkout built before the build root moved out of the tree.
rm -rf build
log "Clean."
