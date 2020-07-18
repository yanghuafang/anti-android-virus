#!/usr/bin/env bash
# Run clang-format over the tracked C/C++ sources (the same file set as CI).
#
#   scripts/format.sh          check only; non-zero exit if anything is unformatted
#   scripts/format.sh --fix    rewrite files in place
#
# Env:
#   CLANG_FORMAT   clang-format binary to use (default: LLVM's, then PATH)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require git
cd "$AAV_ROOT"

FMT="${CLANG_FORMAT:-$(llvm_tool clang-format "$AAV_CLANG_FORMAT_VERSION")}"
[ -n "$FMT" ] || die "clang-format not found. Install LLVM:
  macOS:  brew install llvm
  Ubuntu: sudo apt install clang-format
or run scripts/install-deps-{macos,ubuntu}.sh."

# Print the binary and version: layout heuristics move between clang-format
# majors, so a diff that reproduces on one machine and not another is version
# skew rather than a real slip.
log "Using $FMT — $("$FMT" --version | sed 's/.*version //')"
warn_llvm_skew "$FMT" "$AAV_CLANG_FORMAT_VERSION"

# Word-splitting is intentional (no spaces in these paths). third_party/ is
# excluded, not merely unformatted: reformatting vendored miniz and doctest
# would make every upstream resync an unreadable diff.
#
# The tracked-file listing is the right one -- it is what CI checks -- but it
# needs a repository, and scripts/remote-ubuntu.sh syncs the working tree
# without .git. Fall back to walking the same directories so the check still
# runs there; the two agree on any tree that has no untracked sources.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  files=$(git ls-files '*.cc' '*.h' \
    | grep -E '^(include|src|apps|tests|fuzz|android)/' \
    | grep -v '/third_party/') || true
else
  files=$(find include src apps tests fuzz android \
    \( -name '*.cc' -o -name '*.h' \) -type f 2>/dev/null \
    | sed 's|^\./||' \
    | grep -v '/third_party/' \
    | sort) || true
fi
# Drop paths git still tracks but that are gone from the working tree.
existing=""
for f in $files; do
  [ -f "$f" ] && existing="$existing $f"
done
files="$existing"
[ -n "$files" ] || die "no source files found"

if [ "${1:-}" = "--fix" ]; then
  log "Formatting in place"
  # shellcheck disable=SC2086
  "$FMT" -i $files
  log "Done."
else
  log "Checking (clang-format --dry-run --Werror)"
  # shellcheck disable=SC2086
  "$FMT" --dry-run --Werror $files
  log "All files formatted correctly."
fi
