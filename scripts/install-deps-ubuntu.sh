#!/usr/bin/env bash
# Install the aav build/test toolchain on Debian/Ubuntu.
#
#   scripts/install-deps-ubuntu.sh              host toolchain only
#   scripts/install-deps-ubuntu.sh --android    also the Android SDK/NDK + JDK 17
#   scripts/install-deps-ubuntu.sh --docs-only  just Doxygen + graphviz
#
# Covers everything CI does: the core build (gcc/g++, cmake, zlib), the clang
# matrix, clang-format and clang-tidy (the check jobs), gcovr (coverage), and
# doxygen + graphviz (the API reference). libFuzzer ships with the distro
# clang, so the fuzzer needs no extra package.
#
# clang-format is installed at the major pinned in common.sh
# ($AAV_CLANG_FORMAT_VERSION) rather than unversioned, because it reflows code
# differently between majors and CI has to agree with a developer's editor. That
# major is Ubuntu 24.04's, which is also the pinned runner image, so on 24.04
# the versioned and unversioned packages are the same build.
#
# clang-tidy is taken unversioned: it compiles each file against the host's own
# headers, so the distro's matching build is the one that works. The pinned
# runner image is what makes CI's choice deterministic.
#
# --android adds openjdk-17-jdk (Gradle needs a JDK; nothing else here does),
# then the SDK command-line tools and the versions pinned in
# scripts/android-sdk-packages.txt. It is opt-in because it is a multi-GB
# download that only the two Android scripts need, and because CI gets its SDK
# from android-actions/setup-android instead.
#
# --docs-only is the opposite trim: the two jobs that only render the API
# reference need none of the compilers, and installing them costs a minute per
# run. It exists as a flag rather than as an apt line in the workflow so the
# package names have one home -- a doxygen that needs a companion package tomorrow
# is a change here, not in two workflow files.
#
# The command-line tools come straight from Google rather than from apt: the
# multiverse google-android-*-installer packages lag the pinned NDK and build
# tools, and a mismatch there is a Gradle failure, not a warning. This mirrors
# what the macOS script gets from the android-commandlinetools cask, so both
# platforms end up at the same sdkmanager invocation.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

WANT_ANDROID=0
DOCS_ONLY=0
for a in "$@"; do
  case "$a" in
    --android) WANT_ANDROID=1 ;;
    --docs-only) DOCS_ONLY=1 ;;
    -h | --help)
      sed -n '2,35p' "$0"
      exit 0
      ;;
    *) die "unknown option: $a (try --help)" ;;
  esac
done

[ "$WANT_ANDROID" = "1" ] && [ "$DOCS_ONLY" = "1" ] &&
  die "--android and --docs-only are opposites; pick one"

# After the option loop, so --help answers on the other platform too.
require apt-get

# sudo only when not already root and it is available: CI runners need it, root
# containers do not have it.
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
  doxygen
  graphviz
)
# unzip for the command-line tools archive; curl to fetch it.
[ "$WANT_ANDROID" = "1" ] && PACKAGES+=(openjdk-17-jdk unzip curl)

# Doxygen and dot are already in the list above; --docs-only drops everything
# else rather than naming them a second time.
[ "$DOCS_ONLY" = "1" ] && PACKAGES=(doxygen graphviz)

log "Installing aav build/test dependencies (apt)"
$SUDO apt-get update

# The probe needs the package lists, so it comes after the update rather than
# beside the array above. An archive older than the pinned major has no such
# package; take the unversioned ones there and let warn_llvm_skew report it at
# the point where it changes a result, rather than refusing to install anything.
if [ "$DOCS_ONLY" = "1" ]; then
  : # no clang tools in a docs-only install
elif apt-cache show "clang-format-$AAV_CLANG_FORMAT_VERSION" >/dev/null 2>&1; then
  PACKAGES+=("clang-format-$AAV_CLANG_FORMAT_VERSION" clang-tidy)
else
  warn "this apt archive has no clang-format-$AAV_CLANG_FORMAT_VERSION;
installing the unversioned package. scripts/format.sh will warn when what it
finds does not match the major CI runs."
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

if [ "$DOCS_ONLY" = "1" ]; then
  log "Done: doxygen + graphviz (docs only)."
  exit 0
fi

log "Done: gcc/g++ + cmake + zlib (build), clang + libFuzzer (clang matrix /"
log "fuzz), clang-format + clang-tidy (checks), gcovr (coverage), doxygen +"
log "graphviz (docs)."
[ "$WANT_ANDROID" = "1" ] || log "The Android SDK/NDK is opt-in: re-run with --android."
