#!/usr/bin/env bash
# Install the aav build/test toolchain on Debian/Ubuntu.
#
#   scripts/install-deps-ubuntu.sh              host toolchain only
#   scripts/install-deps-ubuntu.sh --android    also the Android SDK/NDK + JDK 17
#
# Covers the whole toolchain: the core build (gcc/g++, cmake, zlib), the clang
# matrix, clang-format and clang-tidy (the checks) and gcovr (coverage).
# libFuzzer ships with the distro clang, so the fuzzer needs no extra package.
#
# clang-format is installed at the major pinned in common.sh
# ($AAV_CLANG_FORMAT_VERSION) rather than unversioned, because it reflows code
# differently between majors and the check has to agree with a developer's
# editor. That major is Ubuntu 24.04's, so on 24.04 the versioned and
# unversioned packages are the same build.
#
# clang-tidy is taken unversioned: it compiles each file against the host's own
# headers, so the distro's matching build is the one that works.
#
# --android adds openjdk-17-jdk (Gradle needs a JDK; nothing else here does),
# then the SDK command-line tools and the versions pinned in
# scripts/android-sdk-packages.txt. It is opt-in because it is a multi-GB
# download that only the two Android scripts need.
#
# The command-line tools come straight from Google rather than from apt: the
# multiverse google-android-*-installer packages lag the pinned NDK and build
# tools, and a mismatch there is a Gradle failure, not a warning. This mirrors
# what the macOS script gets from the android-commandlinetools cask, so both
# platforms end up at the same sdkmanager invocation.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

WANT_ANDROID=0
for a in "$@"; do
  case "$a" in
    --android) WANT_ANDROID=1 ;;
    -h | --help)
      sed -n '2,28p' "$0"
      exit 0
      ;;
    *) die "unknown option: $a (try --help)" ;;
  esac
done

# After the option loop, so --help answers on the other platform too.
require apt-get

# sudo only when not already root and it is available: an unprivileged user
# needs it, a root container does not have it.
SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
fi

PACKAGES=(
  build-essential
  cmake
  zlib1g-dev
  clang
  gcovr
)
# unzip for the command-line tools archive; curl to fetch it.
[ "$WANT_ANDROID" = "1" ] && PACKAGES+=(openjdk-17-jdk unzip curl)

log "Installing aav build/test dependencies (apt)"
$SUDO apt-get update

# The probe needs the package lists, so it comes after the update rather than
# beside the array above. An archive older than the pinned major has no such
# package; take the unversioned ones there and let warn_llvm_skew report it at
# the point where it changes a result, rather than refusing to install anything.
if apt-cache show "clang-format-$AAV_CLANG_FORMAT_VERSION" >/dev/null 2>&1; then
  PACKAGES+=("clang-format-$AAV_CLANG_FORMAT_VERSION" clang-tidy)
else
  warn "this apt archive has no clang-format-$AAV_CLANG_FORMAT_VERSION;
installing the unversioned package. scripts/format.sh will warn when what it
finds does not match the pinned major."
  PACKAGES+=(clang-format clang-tidy)
fi

$SUDO apt-get install -y "${PACKAGES[@]}"

if [ "$WANT_ANDROID" = "1" ]; then
  # Under the user's home, so no step here needs root. ANDROID_HOME wins if it
  # is already set, which is what makes a re-run land in the existing SDK.
  SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
  TOOLS="$SDK/cmdline-tools/latest"

  if [ ! -x "$TOOLS/bin/sdkmanager" ]; then
    # dl.google.com has no "latest" alias: every command-line tools archive
    # carries a build number, so bootstrapping needs one pinned here. It is
    # only a bootstrap -- these tools immediately install "cmdline-tools;latest"
    # into the SDK, and that copy is what everything afterwards uses, so the
    # pin does not decide which tools you end up with. Bump it if the download
    # starts 404ing; the current number is on
    # https://developer.android.com/studio#command-tools.
    BOOTSTRAP_ZIP="commandlinetools-linux-13114758_latest.zip"
    URL="https://dl.google.com/android/repository/$BOOTSTRAP_ZIP"

    log "Bootstrapping the SDK command-line tools -> $SDK"
    WORK="$(mktemp -d)"
    trap 'rm -rf "$WORK"' EXIT
    curl -fsSL -o "$WORK/tools.zip" "$URL" ||
      die "download failed: $URL
Fetch the Linux command-line tools by hand from
https://developer.android.com/studio#command-tools and unzip them so that
$TOOLS/bin/sdkmanager exists, then re-run this script."
    unzip -q "$WORK/tools.zip" -d "$WORK"

    # The archive unpacks to a bare cmdline-tools/, which is not a layout
    # sdkmanager can install into itself -- it wants cmdline-tools/<channel>/.
    # Let the unpacked copy lay that out, rather than moving directories by
    # hand and guessing at the structure it expects.
    run_sdkmanager "$WORK/cmdline-tools/bin/sdkmanager" "$SDK" "cmdline-tools;latest"
    [ -x "$TOOLS/bin/sdkmanager" ] || die "bootstrap did not produce $TOOLS/bin/sdkmanager"
  else
    log "Command-line tools already at $TOOLS"
  fi

  install_android_sdk "$SDK"
fi

log "Done: gcc/g++ + cmake + zlib (build), clang + libFuzzer (clang matrix /"
log "fuzz), clang-format + clang-tidy (checks), gcovr (coverage)."
[ "$WANT_ANDROID" = "1" ] || log "The Android SDK/NDK is opt-in: re-run with --android."
