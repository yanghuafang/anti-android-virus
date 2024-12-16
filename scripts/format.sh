#!/usr/bin/env bash
# Run clang-format over the tracked C/C++ sources (same file set as CI).
#
#   scripts/format.sh          check only; non-zero exit if anything is unformatted
#   scripts/format.sh --fix    rewrite files in place
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require clang-format
require git
cd "$AAV_ROOT"

# Word-splitting is intentional (paths have no spaces); mirrors the CI filter.
files=$(git ls-files '*.cc' '*.h' \
  | grep -E '^(include|src|apps|tests|fuzz|android)/' \
  | grep -v '/third_party/') || true
# Drop paths still tracked in git but already removed from the working tree
# (e.g. a deletion that hasn't been committed yet).
existing=""
for f in $files; do
  [ -f "$f" ] && existing="$existing $f"
done
files="$existing"
[ -n "$files" ] || die "no source files found"

if [ "${1:-}" = "--fix" ]; then
  log "Formatting in place"
  # shellcheck disable=SC2086
  clang-format -i $files
  log "Done."
else
  log "Checking (clang-format --dry-run --Werror)"
  # shellcheck disable=SC2086
  clang-format --dry-run --Werror $files
  log "All files formatted correctly."
fi
