#!/usr/bin/env bash
# remote-ubuntu.sh — run any of these scripts on the Ubuntu box.
#
# aav claims Linux and macOS, and parts of that claim cannot be checked from a
# Mac at all:
#
#   * asan.sh's leak checking. LeakSanitizer rides along with ASan on Linux
#     only, so the Destroy()/ObjPtr ownership the CI asan job verifies is simply
#     not verified by the same script run here.
#   * coverage.sh against gcc/gcov. macOS has no gcc, so a local run measures
#     clang's counters through an llvm-cov shim -- close, but not the numbers
#     COVERAGE_FAIL_UNDER gates on.
#   * fuzz.sh without Homebrew LLVM: on Linux the distro clang carries
#     libFuzzer, which is the configuration CI builds.
#   * install-deps-ubuntu.sh, which by definition only runs on Debian/Ubuntu.
#
# Rather than push a branch and wait for a runner to disagree, this runs a
# command on the Linux host, optionally mirroring the working tree --
# uncommitted edits included -- first.
#
#   ./remote-ubuntu.sh ./test.sh                  # run what is there
#   ./remote-ubuntu.sh --sync ./asan.sh           # copy first, then run
#   ./remote-ubuntu.sh --sync                     # copy and stop
#   ./remote-ubuntu.sh --clone ./test.sh          # clone, then run
#   ./remote-ubuntu.sh --shell './test.sh | tail'  # shell text, not an argv
#
# Copying is opt-in rather than the default because it is the only step that
# destroys anything: it is rsync --delete against the remote checkout, so
# whatever is there is made to match this machine exactly. A command that only
# builds or reads should not have to think about that.
#
# --sync and --clone answer the same question -- where does the remote tree come
# from -- with different answers, so asking for both is a contradiction rather
# than a sequence, and is refused. --sync sends what is on this machine,
# uncommitted work and all; --clone fetches what is pushed to GitHub, which is
# the honest way to check that what was committed is what actually builds.
#
# Everything runs in the remote scripts/ directory -- both a bare command and
# --shell -- because that is where this script is run from, so a sibling is
# just ./test.sh either way. Every script here resolves the repo root from its
# own path, so none of them care where they are invoked. A probe about the
# checkout as a whole starts with a cd:
#   ./remote-ubuntu.sh --shell 'cd .. && git status'
#
# The remote path mirrors the local one by default, so $AAV_BUILD_ROOT -- the
# sibling anti-android-virus-build/ that common.sh derives -- lands in the same
# place relative to the checkout on both hosts, and nothing has to be told
# twice. It is also why the transfer needs no build-directory exclusions: since
# nothing generated is written inside the tree any more, there is nothing there
# to leave out.
#
# --sync is also the answer when the host cannot reach GitHub: it moves the tree
# over ssh from this machine, so nothing on the host has to clone anything.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

REMOTE_HOST="${AAV_REMOTE_HOST:-yanghuafang@192.168.10.13}"
REMOTE_DIR="${AAV_REMOTE_DIR:-study-projects/anti-android-virus}"
REPO_URL="${AAV_REPO_URL:-https://github.com/yanghuafang/anti-android-virus.git}"

usage() {
  cat <<'EOF'
Usage: ./remote-ubuntu.sh [--sync | --clone] [--shell] [command ...]

Run a command on the Ubuntu host, optionally putting a tree there first. Run it
from scripts/, like the scripts it forwards. The reason it exists is the
Linux-only half of CI: ASan's leak checking, coverage against gcc/gcov,
libFuzzer from the distro clang, and install-deps-ubuntu.sh.

  ./remote-ubuntu.sh ./test.sh          Run; copy nothing.
  ./remote-ubuntu.sh --sync ./asan.sh   Copy this tree over, then run.
  ./remote-ubuntu.sh --sync             Copy this tree over and stop.
  ./remote-ubuntu.sh --clone ./test.sh  Clone from GitHub, then run.
  ./remote-ubuntu.sh --shell 'nproc'    Run shell text, not an argv.

Options:
  --sync      Mirror this working tree to the host before running. This is
              rsync --delete: the remote checkout is made to match this one, so
              anything edited only on the host is lost.
  --clone     git clone the repository onto the host instead. Refuses to
              overwrite an existing checkout. Mutually exclusive with --sync.
  --shell     Treat the argument as shell text rather than a list of
              arguments, so pipes and semicolons work. Runs in the remote
              scripts/, same as a bare command; prefix 'cd .. && ' for the
              repo root.
  -h, --help  Show this help.

Environment:
  AAV_REMOTE_HOST  user@host to reach (default: yanghuafang@192.168.10.13).
  AAV_REMOTE_DIR   Checkout path on the host, relative to its home directory
                   (default: study-projects/anti-android-virus, mirroring the
                   macOS layout so the sibling build root matches). --sync
                   deletes whatever else lives there, so give it a path of its
                   own.
  AAV_REPO_URL     What --clone clones. Set it to
                   git@github.com:yanghuafang/anti-android-virus.git to clone
                   over ssh, which uses the forwarded agent from this machine.
EOF
}

do_sync=false
do_clone=false
as_shell=false

while [ $# -gt 0 ]; do
  case "$1" in
    --sync) do_sync=true; shift ;;
    --clone) do_clone=true; shift ;;
    --shell) as_shell=true; shift ;;
    -h | --help) usage; exit 0 ;;
    --) shift; break ;;
    *) break ;;
  esac
done

require ssh

if [ "$do_sync" = true ] && [ "$do_clone" = true ]; then
  die "--sync and --clone are mutually exclusive: one sends this working tree,
the other fetches what is pushed to GitHub. Pick one."
fi

# Nothing to run and nothing to put there is a mistake worth naming rather than
# a silent success. Checked before any transfer, so a typo costs nothing.
if [ $# -eq 0 ] && [ "$do_sync" = false ] && [ "$do_clone" = false ]; then
  usage >&2
  die "nothing to do: give a command, or --sync/--clone to place a tree."
fi

if [ "$do_clone" = true ]; then
  # git clone into an existing directory fails anyway, but it fails after the
  # connection with a message about the destination not being empty. Checking
  # first says the useful thing: which directory, and what to do about it. It is
  # deliberately not resolved by deleting anything -- that checkout may be the
  # only copy of something.
  if ssh "$REMOTE_HOST" "[ -e '$REMOTE_DIR' ]"; then
    die "$REMOTE_HOST:$REMOTE_DIR already exists; refusing to clone over it.
Remove it on the host, or point AAV_REMOTE_DIR somewhere else."
  fi
  log "Cloning $REPO_URL -> $REMOTE_HOST:$REMOTE_DIR/"
  # -A forwards this machine's SSH agent, so an ssh-form AAV_REPO_URL
  # authenticates with the key that already reaches GitHub from here and the
  # host needs none of its own. It is scoped to the clone rather than the whole
  # script because while connected, the host can use that agent.
  if ! ssh -A "$REMOTE_HOST" \
    "mkdir -p \"\$(dirname '$REMOTE_DIR')\" && git clone '$REPO_URL' '$REMOTE_DIR'"; then
    die "clone failed. The three causes seen here, with different fixes:
  * No route to github.com from the host. Use --sync instead: it sends this
    working tree over ssh and never touches GitHub.
  * 'Permission denied (publickey)' with an ssh AAV_REPO_URL -- no key in the
    forwarded agent. Run 'ssh-add' here, check with 'ssh-add -l'.
  * git not installed on the host. Run scripts/install-deps-ubuntu.sh there
    first."
  fi
fi

if [ "$do_sync" = true ]; then
  require rsync
  log "Syncing $AAV_ROOT/ -> $REMOTE_HOST:$REMOTE_DIR/"
  ssh "$REMOTE_HOST" "mkdir -p '$REMOTE_DIR'"
  # --delete so a file deleted here does not linger and keep building there.
  #
  # .git/ because this machine is the source of truth for history. The rest is
  # host-specific state that would be actively wrong on the far side: a CMake
  # cache and compile_commands.json record absolute paths and a compiler
  # identity from the machine that wrote them, and the generated samples are
  # whatever sigtool last produced here. Everything under $AAV_BUILD_ROOT is
  # already outside this transfer -- see the header comment -- so the build
  # directories named here are only the in-tree leftovers a checkout from
  # before that change still has.
  #
  # The leading slash anchors a pattern to the transfer root; the unanchored
  # ones are meant to match at any depth, which is how android/app/build and a
  # stray .cache/ are caught wherever they turn up.
  rsync -az --delete \
    --exclude '/.git/' \
    --exclude '/.claude/' \
    --exclude '.cache/' \
    --exclude 'compile_commands.json' \
    --exclude 'build/' \
    --exclude '.gradle/' \
    --exclude '.cxx/' \
    --exclude '/samples/sample.dex' \
    --exclude '/samples/sample.sig' \
    --exclude '.DS_Store' \
    --exclude '._*' \
    "$AAV_ROOT/" "$REMOTE_HOST:$REMOTE_DIR/"
fi

# --sync or --clone with no command is the "just put it there" case.
if [ $# -eq 0 ]; then
  exit 0
fi

# Both forms run where the scripts live, so ./test.sh means the same thing
# whether it is sent as an argv or as shell text.
remote_cwd="$REMOTE_DIR/scripts"

# Two different things are being sent, and they need opposite treatment. A
# command is a list of arguments: %q escapes each one so a path with a space
# survives the two shells this crosses. --shell is a snippet the caller wrote to
# be interpreted -- its pipes and semicolons are the point -- so quoting it
# would turn the whole line into one nonexistent filename.
if [ "$as_shell" = true ]; then
  remote_cmd="$*"
else
  remote_cmd="$(printf '%q ' "$@")"
fi

# Ask for a remote TTY only when there is a local one to mirror, so a build run
# from a terminal keeps its progress output live, and one run from a script does
# not open with ssh complaining that stdin is not a terminal.
tty_flag=()
if [ -t 0 ]; then
  tty_flag=(-t)
fi

# A login shell, so the command starts from the PATH the host's profile builds.
# `ssh host cmd` runs a shell that is neither login nor interactive: the profile
# is never read, and Ubuntu's stock ~/.bashrc returns on its first line for
# exactly that case. That matters here because install-deps-ubuntu.sh --android
# tells you to export ANDROID_HOME, ANDROID_NDK_HOME and a cmdline-tools PATH
# from your profile, and without this every Android script would fail as
# "NDK path not set" on a host that is set up correctly.
#
# The +"..." guard is for the empty case: macOS still ships bash 3.2, where
# expanding an empty array under `set -u` is an unbound-variable error rather
# than nothing at all.
exec ssh ${tty_flag[@]+"${tty_flag[@]}"} "$REMOTE_HOST" \
  "bash -lc 'cd $remote_cwd && $remote_cmd'"
