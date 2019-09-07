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
