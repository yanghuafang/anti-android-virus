# Shared helpers for the aav dev scripts. Source this from the other scripts:
#   source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
# Sets strict mode, resolves the repo root as $AAV_ROOT and the build root as
# $AAV_BUILD_ROOT, defines logging.

set -euo pipefail

AAV_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Everything generated lands here, outside the source tree, so the checkout only
# ever holds tracked files. The default is a sibling of the repo, and
# CMakePresets.json hard-codes the same one so `cmake --preset` and the scripts
# agree.
AAV_BUILD_ROOT="${AAV_BUILD_ROOT:-$(cd "$AAV_ROOT/.." && pwd)/anti-android-virus-build}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || die "'$1' not found in PATH"; }

# The clang-format major this project pins, and the reason only clang-format is
# pinned.
#
# clang-format reflows code differently between majors, and it is a hard gate:
# skew means a check rejects exactly what a developer's editor just wrote. It is
# also safe to pin, because clang-format never compiles anything -- it lexes, so
# an older one is not bothered by a newer platform SDK.
#
# clang-tidy is the opposite on both counts. It compiles each translation unit,
# so it has to be new enough for the host's standard library: clang-tidy 18
# cannot parse a current macOS SDK's libc++ at all. And its findings are
# advisory in a way formatting is not. So it floats to whatever the host can
# actually run.
AAV_CLANG_FORMAT_VERSION="${AAV_CLANG_FORMAT_VERSION:-18}"

# llvm_tool <name> [major] — echo the path to an LLVM tool, or empty if absent.
#
# With a major, that version is looked for first, so a machine carrying several
# LLVMs still agrees with everyone else. Without one, the newest thing on hand
# wins. Debian and Ubuntu install versioned binaries beside the unversioned
# ones; Homebrew keeps every llvm keg-only, so its bin is not on PATH and
# `clang-format` would otherwise resolve to nothing (Xcode ships neither
# clang-format nor clang-tidy).
llvm_tool() {
  local name="$1" want="${2:-}" prefix formula
  if [ -n "$want" ]; then
    if command -v "$name-$want" >/dev/null 2>&1; then
      command -v "$name-$want"
      return
    fi
    if command -v brew >/dev/null 2>&1; then
      prefix="$(brew --prefix "llvm@$want" 2>/dev/null || true)"
      if [ -n "$prefix" ] && [ -x "$prefix/bin/$name" ]; then
        echo "$prefix/bin/$name"
        return
      fi
    fi
  fi
  if command -v brew >/dev/null 2>&1; then
    prefix="$(brew --prefix llvm 2>/dev/null || true)"
    if [ -n "$prefix" ] && [ -x "$prefix/bin/$name" ]; then
      echo "$prefix/bin/$name"
      return
    fi
  fi
  command -v "$name" 2>/dev/null || true
}

# warn_llvm_skew <binary> <major> — warn when a tool is not the pinned major.
#
# A warning rather than an error: an older or newer clang-format still formats,
# and refusing to run would leave someone with no way to format anything. What
# it prevents is the confusing half of the failure -- a clean run here and a
# rejection elsewhere, with nothing on screen saying why.
warn_llvm_skew() {
  local bin="$1" want="$2" got
  got="$("$bin" --version 2>/dev/null | sed -n 's/.*version \([0-9][0-9]*\).*/\1/p' | head -1)"
  [ -n "$got" ] || return 0
  [ "$got" = "$want" ] && return 0
  warn "$(basename "$bin") is major $got, but this project pins $want.
Formatting may differ from what the check expects, or set
AAV_CLANG_FORMAT_VERSION=$got."
}
