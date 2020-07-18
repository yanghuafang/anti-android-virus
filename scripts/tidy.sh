#!/usr/bin/env bash
# Run clang-tidy over aav's own sources (third_party/ is never analyzed).
#
#   scripts/tidy.sh                     report findings; non-zero exit if any
#   scripts/tidy.sh --fix               apply the automatic fixes, then re-format
#   scripts/tidy.sh src/dex/dex_file.cc limit the run to specific files
#
# The check list is ../.clang-tidy, which also records what is disabled and why.
#
# Env:
#   BUILD_DIR   existing build tree with compile_commands.json; defaults to the
#               debug preset's, which is also what gets built if none is there
#   CLANG_TIDY  clang-tidy binary to use (default: LLVM's, then PATH)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require cmake
require python3
cd "$AAV_ROOT"

BUILD_DIR="${BUILD_DIR:-$AAV_PRESET_ROOT/debug}"

FIX=0
FILES=()
for a in "$@"; do
  case "$a" in
    --fix) FIX=1 ;;
    -h | --help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
    *) FILES+=("$a") ;;
  esac
done

TIDY="${CLANG_TIDY:-$(llvm_tool clang-tidy)}"
[ -n "$TIDY" ] || die "clang-tidy not found. Install LLVM:
  macOS:  brew install llvm
  Ubuntu: sudo apt install clang-tidy
or run scripts/install-deps-{macos,ubuntu}.sh."

# Same reason as format.sh: check names and diagnostics move between majors.
# Unpinned, unlike clang-format: clang-tidy compiles each file, so it has to be
# new enough for the host's standard library headers -- an older one fails to
# parse them rather than reporting on this project. CI's Linux run is the
# authoritative one; a different major here may say more or less.
log "Using $TIDY — $("$TIDY" --version | sed -n 's/.*version /clang-tidy /p' | head -1)"

# A .clang-tidy that fails to parse -- an unknown key from a newer clang-tidy,
# say -- is not an error to clang-tidy: it discards the file and falls back to
# its built-in defaults, which are clang-analyzer-*. The run then reports checks
# this project never enabled, or passes while enforcing the wrong list. Ask what
# is actually enabled and confirm it is ours.
ENABLED="$("$TIDY" --list-checks 2>/dev/null || true)"
if ! grep -q 'google-readability-casting' <<<"$ENABLED"; then
  echo "$ENABLED" | head -20 >&2
  die "$AAV_ROOT/.clang-tidy is not in effect (see the enabled checks above).
Usually an unknown key for this clang-tidy version; run '$TIDY --list-checks'
from the repo root to see the parse error."
fi

DB="$BUILD_DIR/compile_commands.json"
if [ ! -f "$DB" ]; then
  log "No compile database at $BUILD_DIR; building one"
  "$AAV_ROOT/scripts/build.sh" >/dev/null
fi
[ -f "$DB" ] || die "no compile database at $DB (run scripts/build.sh)"

# Take the file list from the database rather than from `find`, so it always
# matches what the build actually compiled.
if [ ${#FILES[@]} -eq 0 ]; then
  while IFS= read -r f; do FILES+=("$f"); done < <(python3 - "$DB" <<'PY'
import json, os, sys
db = json.load(open(sys.argv[1]))
root = os.getcwd()
for f in sorted({e["file"] for e in db}):
    if "third_party" not in f:
        print(os.path.relpath(f, root))
PY
  )
fi
[ ${#FILES[@]} -gt 0 ] || die "no sources to analyze"

# A file the database does not mention is the quiet way for this check to pass
# while analyzing nothing: clang-tidy may skip it, guess a command from a
# sibling entry, or exit 0 with no output. Only the first is detectable
# afterwards, so check membership up front. This is the state the tree is in
# when a source is added without re-running CMake.
MISSING=()
for f in "${FILES[@]}"; do
  if [ ! -f "$f" ]; then
    MISSING+=("$f — no such file")
  elif ! grep -qF "\"$AAV_ROOT/$f\"" "$DB"; then
    MISSING+=("$f — not in the compile database")
  fi
done
if [ ${#MISSING[@]} -gt 0 ]; then
  printf 'clang-tidy cannot analyze %d of %d file(s):\n' "${#MISSING[@]}" "${#FILES[@]}" >&2
  printf '  %s\n' "${MISSING[@]}" >&2
  die "re-run scripts/build.sh to refresh $DB"
fi

# Homebrew's clang-tidy does not know the macOS SDK location; without this
# every file fails to parse on the standard library headers.
EXTRA=()
if [ "$(uname -s)" = "Darwin" ] && command -v xcrun >/dev/null 2>&1; then
  EXTRA+=("--extra-arg=-isysroot$(xcrun --show-sdk-path)")
fi

ARGS=(-p "$BUILD_DIR" --quiet "${EXTRA[@]}")
[ "$FIX" = "1" ] && ARGS+=(--fix --fix-errors)

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aav-tidy-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# Findings go to stdout; progress and "could not analyze" reasons go to stderr.
# Keep them apart so a broken run is distinguishable from a clean one: pass/fail
# needs all three of stdout, stderr and the exit status, since any one alone
# misses what the others catch. `|| STATUS=$?` because a non-zero clang-tidy is
# expected here and `set -e` would abort before the status could be read.
log "Running clang-tidy over ${#FILES[@]} file(s)"
STATUS=0
"$TIDY" "${ARGS[@]}" "${FILES[@]}" >"$WORK/out" 2>"$WORK/err" || STATUS=$?

FINDINGS=0
if [ -s "$WORK/out" ]; then
  cat "$WORK/out"
  FINDINGS=1
fi

BROKEN=0
# Filter only the known-benign progress lines, so an unfamiliar stderr message
# surfaces instead of being swallowed. `|| true` because grep exits 1 when it
# prints nothing, which is the normal outcome on a clean run.
grep -vE '^(\[[0-9]+/[0-9]+\] Processing file |[0-9]+ warnings? generated\.|Suppressed [0-9]+ warnings? |clang-tidy applied )' \
  "$WORK/err" >"$WORK/err-notable" || true
if [ -s "$WORK/err-notable" ]; then
  echo "clang-tidy wrote to stderr:" >&2
  cat "$WORK/err-notable" >&2
fi
if grep -qE 'Compile command not found|Error while processing|unable to handle compilation|Error while trying to load a compilation database|Error parsing .*\.clang-tidy|unknown key' "$WORK/err"; then
  echo "clang-tidy could not analyze one or more files (see stderr above)." >&2
  BROKEN=1
fi
if [ "$STATUS" -ne 0 ]; then
  echo "clang-tidy exited $STATUS." >&2
  BROKEN=1
fi

if [ "$FIX" = "1" ]; then
  # clang-tidy's rewrites do not respect .clang-format line breaking.
  "$AAV_ROOT/scripts/format.sh" --fix >/dev/null
  log "Applied fixes and re-formatted."
  exit "$BROKEN"
fi

if [ "$FINDINGS" = "0" ] && [ "$BROKEN" = "0" ]; then
  log "No findings (${#FILES[@]} file(s) analyzed)."
  exit 0
fi
exit 1
