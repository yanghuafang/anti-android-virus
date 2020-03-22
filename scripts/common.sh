# Shared helpers for the aav dev scripts. Source this from the other scripts:
#   source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
# Sets strict mode, resolves the repo root as $AAV_ROOT and the build root as
# $AAV_BUILD_ROOT, defines logging.

set -euo pipefail

AAV_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Everything generated -- CMake trees, Android/NDK output, the Gradle build
# directories and project cache, the Doxygen site -- lands here, outside the
# source tree, so the checkout only ever holds tracked files. The default is a
# sibling of the repo; override it to move the output that is not produced by a
# CMake preset:
#   AAV_BUILD_ROOT=/tmp/aav scripts/android.sh
# CMakePresets.json and android/build.gradle hard-code the same default, so
# `cmake --preset` and a bare `./gradlew` agree with the scripts. See
# $AAV_PRESET_ROOT below for what an override does not move, and why.
AAV_BUILD_ROOT="${AAV_BUILD_ROOT:-$(cd "$AAV_ROOT/.." && pwd)/anti-android-virus-build}"

# Where the CMake presets configure into, which is not the same question as
# $AAV_BUILD_ROOT above and cannot be made into the same question.
#
# CMakePresets.json anchors every binaryDir to ${sourceDir}/.. because a preset
# has no way to read an environment variable *with a fallback*: $env{} is empty
# when the variable is unset, so honouring an override would break a bare
# `cmake --preset debug`. The preset trees therefore stay put while the NDK,
# Gradle and Doxygen output -- none of which goes through a preset -- follows
# $AAV_BUILD_ROOT wherever it is pointed.
#
# Scripts that need to name a preset's tree afterwards (gcovr's input, the
# fuzzer binary, the compile database) use this. Using $AAV_BUILD_ROOT for that
# is how an override turns into a script reading a directory CMake never wrote.
# Move this and CMakePresets.json together, or neither.
AAV_PRESET_ROOT="$(cd "$AAV_ROOT/.." && pwd)/anti-android-virus-build"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || die "'$1' not found in PATH"; }

# android_sdk_packages — echo the pinned sdkmanager package list, one per line.
# The list itself lives in scripts/android-sdk-packages.txt, which explains why
# each version is what it is.
android_sdk_packages() {
  grep -Ev '^[[:space:]]*(#|$)' "$AAV_ROOT/scripts/android-sdk-packages.txt"
}

# run_sdkmanager <sdkmanager> <sdk_root> [args...] — run sdkmanager unattended.
#
# Every package is gated behind a license prompt and `yes |` is the documented
# way through it, but `yes` takes SIGPIPE once sdkmanager stops reading and
# `set -o pipefail` would report that as a failed pipeline. Judge the run by
# sdkmanager's own status instead.
run_sdkmanager() {
  local bin="$1" sdk="$2" rc=0
  shift 2
  yes | "$bin" --sdk_root="$sdk" "$@" || rc="${PIPESTATUS[1]}"
  [ "$rc" -eq 0 ] || die "sdkmanager $* failed (exit $rc)"
}

# install_android_sdk <sdk_root> — accept the licenses and install the pinned
# packages into an SDK that already has cmdline-tools/latest, then print the
# environment scripts/android.sh and Gradle need.
#
# The NDK has to land inside the SDK, not beside it: scripts/android.sh reads
# $ANDROID_NDK_HOME and would take a standalone NDK, but AGP resolves the
# ndkVersion pin from $ANDROID_HOME/ndk/<version> and accepts nothing else.
# Installing it with sdkmanager is what satisfies both.
install_android_sdk() {
  local sdk="$1" bin="$1/cmdline-tools/latest/bin/sdkmanager"
  [ -x "$bin" ] || die "no sdkmanager at $bin (command-line tools not installed)"

  # --licenses prints every license in full, which is not what anyone ran this
  # script to read; the install below is the part worth watching.
  log "Accepting SDK licenses"
  run_sdkmanager "$bin" "$sdk" --licenses >/dev/null

  local pkgs=()
  while IFS= read -r pkg; do pkgs+=("$pkg"); done < <(android_sdk_packages)
  log "Installing SDK packages: ${pkgs[*]}"
  run_sdkmanager "$bin" "$sdk" "${pkgs[@]}"

  local ndk
  ndk="$(android_sdk_packages | sed -n 's/^ndk;//p')"
  log "Done. Add to your profile:"
  log "  export ANDROID_HOME=\"$sdk\""
  log "  export ANDROID_NDK_HOME=\"$sdk/ndk/$ndk\""
  log "  export PATH=\"$sdk/cmdline-tools/latest/bin:\$PATH\""
}

# The clang-format major this project pins, and the reason only clang-format is
# pinned.
#
# clang-format reflows code differently between majors, and it is a hard gate:
# skew means CI rejects exactly what a developer's editor just wrote. It is also
# safe to pin, because clang-format never compiles anything -- it lexes, so an
# older one is not bothered by a newer platform SDK.
#
# clang-tidy is the opposite on both counts. It compiles each translation unit,
# so it has to be new enough for the host's standard library: clang-tidy 18
# cannot parse the macOS 26 SDK's libc++ at all, which uses __builtin_clzg from
# Clang 19. And its findings are advisory in a way formatting is not. So it
# floats to whatever the host can actually run, and CI's Linux run -- pinned by
# the runner image rather than by a version here -- is the authoritative one.
#
# 18 is Ubuntu 24.04's, which is the pinned CI image, so Linux gets the pin from
# the archive and macOS gets it from the llvm@18 keg. Moving this number means
# moving the runner image with it.
AAV_CLANG_FORMAT_VERSION="${AAV_CLANG_FORMAT_VERSION:-18}"

# llvm_tool <name> [major] — echo the path to an LLVM tool, or empty if absent.
#
# With a major, that version is looked for first, so a machine carrying several
# LLVMs still agrees with CI. Without one, the newest thing on hand wins.
# Debian and Ubuntu install versioned binaries beside the unversioned ones;
# Homebrew keeps every llvm keg-only, so its bin is not on PATH and
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
# it prevents is the confusing half of the failure -- a clean local run and a
# red pull request, with nothing on screen saying why.
warn_llvm_skew() {
  local bin="$1" want="$2" got
  got="$("$bin" --version 2>/dev/null | sed -n 's/.*version \([0-9][0-9]*\).*/\1/p' | head -1)"
  [ -n "$got" ] || return 0
  [ "$got" = "$want" ] && return 0
  warn "$(basename "$bin") is major $got, but CI runs $want.
Formatting may differ from what the check expects. Install the pinned tool with
scripts/install-deps-{macos,ubuntu}.sh, or set AAV_CLANG_FORMAT_VERSION=$got."
}
