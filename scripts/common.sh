# Shared helpers for the aav dev scripts. Source this from the other scripts:
#   source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
# It sets strict mode, resolves the repo root as $AAV_ROOT, and defines logging.

set -euo pipefail

# Repo root = the parent of the directory holding this file.
AAV_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# require <cmd> — abort with a friendly message if a tool is missing.
require() { command -v "$1" >/dev/null 2>&1 || die "'$1' not found in PATH"; }
