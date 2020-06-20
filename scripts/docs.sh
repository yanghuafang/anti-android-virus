#!/usr/bin/env bash
# Generate aav's API reference with Doxygen.
#
#   scripts/docs.sh          build the site into $AAV_BUILD_ROOT/docs/html
#   scripts/docs.sh --open   build it, then open the index in a browser
#
# Documents what carries a /// comment: the public SDK headers under
# include/aav and the internal object API under src/api/aav. Output goes to
# $AAV_BUILD_ROOT/docs, outside the checkout -- nothing generated is committed.
#
# Pass/fail comes from the warning log, not the exit status: Doxygen exits 0
# after complaining about a broken reference, so a green run means nothing on
# its own.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

cd "$AAV_ROOT"

WANT_OPEN=0
for a in "$@"; do
  case "$a" in
    --open) WANT_OPEN=1 ;;
    -h | --help)
      sed -n '2,17p' "$0"
      exit 0
      ;;
    *) die "unknown option: $a (try --help)" ;;
  esac
done

command -v doxygen >/dev/null 2>&1 || die "doxygen not found. See docs/Building.md.
  macOS:  brew install doxygen
  Ubuntu: sudo apt install doxygen
or run scripts/install-deps-{macos,ubuntu}.sh."

# HAVE_DOT is on, and a missing dot silently drops every diagram rather than
# failing, so catch it up front.
command -v dot >/dev/null 2>&1 || die "graphviz's dot not found; the Doxyfile sets HAVE_DOT=YES.
  macOS:  brew install graphviz
  Ubuntu: sudo apt install graphviz"

# Doxygen's warnings move between releases; record which binary produced them.
log "Using $(command -v doxygen) — Doxygen $(doxygen --version)"

# The Doxyfile reads $(AAV_DOCS_DIR) for OUTPUT_DIRECTORY and WARN_LOGFILE,
# which is why doxygen is invoked from here rather than by hand.
DOCS_DIR="$AAV_BUILD_ROOT/docs"
export AAV_DOCS_DIR="$DOCS_DIR"
LOG="$DOCS_DIR/doxygen-warnings.log"

# WARN_LOGFILE is opened before Doxygen creates OUTPUT_DIRECTORY.
mkdir -p "$DOCS_DIR"
rm -f "$LOG"

# Doxygen does not clear html/, so a page that stops being generated keeps
# being served locally. Clear it so the local site matches what CI publishes
# from a fresh runner. Only html/ goes: the warning log lives beside it.
rm -rf "$DOCS_DIR/html"

log "Generating API reference"
doxygen docs/doxygen/Doxyfile

if [ -s "$LOG" ]; then
  echo "Doxygen reported problems:" >&2
  cat "$LOG" >&2
  die "documentation build is not clean (see $LOG)"
fi

log "Documentation written to $DOCS_DIR/html/index.html"

if [ "$WANT_OPEN" = "1" ]; then
  if command -v open >/dev/null 2>&1; then
    open "$DOCS_DIR/html/index.html"
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$DOCS_DIR/html/index.html"
  fi
fi
