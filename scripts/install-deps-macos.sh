#!/usr/bin/env bash
# Install the aav build/test toolchain on macOS (Homebrew).
#
#   scripts/install-deps-macos.sh             host toolchain only
#   scripts/install-deps-macos.sh --android   also the Android SDK/NDK + JDK 17
#
# The base compiler and zlib come with the Xcode Command Line Tools -- run
# `xcode-select --install` first if you don't have them. This adds:
#   cmake     - build system
#   llvm      - clang-tidy (Xcode ships neither it nor clang-format), plus a
#               clang++ carrying the libFuzzer runtime Apple Clang lacks
#   llvm@18   - clang-format only, at the major CI runs. Formatting is a hard
#               gate and clang-format reflows differently between majors, so an
#               unpinned one means CI rejects what your editor just wrote.
#               clang-tidy is deliberately not taken from this keg: it compiles
#               each file, and 18 cannot parse a current macOS SDK's libc++.
#   gcovr     - coverage report
#   doxygen   - API reference (scripts/docs.sh)
#   graphviz  - the Doxyfile sets HAVE_DOT, so its diagrams need `dot`
#
# Both kegs are keg-only, so nothing here shadows Apple Clang; format.sh and
# tidy.sh find the tools inside them by path, via llvm_tool in common.sh.
#
# --android additionally installs openjdk@17 (Gradle) and the SDK command-line
# tools, then sdkmanager-installs the versions pinned in
# scripts/android-sdk-packages.txt. It is opt-in because it is a multi-GB
# download that only the two Android scripts need.
#
# Not the `android-ndk` cask: it puts a standalone NDK outside the SDK, which
# scripts/android.sh accepts but the Gradle app build does not -- see
# install_android_sdk in common.sh. Not the `android-studio` cask either; the
# IDE brings its own SDK manager and is a separate choice from a build toolchain.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

WANT_ANDROID=0
for a in "$@"; do
  case "$a" in
    --android) WANT_ANDROID=1 ;;
    -h | --help)
      sed -n '2,32p' "$0"
      exit 0
      ;;
    *) die "unknown option: $a (try --help)" ;;
  esac
done

# After the option loop, so --help answers on the other platform too.
require brew

log "Installing aav build/test dependencies (brew)"
brew install cmake llvm "llvm@$AAV_CLANG_FORMAT_VERSION" gcovr doxygen graphviz

if [ "$WANT_ANDROID" = "1" ]; then
  # The formula, not the temurin cask: it installs without sudo, and Gradle
  # only needs JAVA_HOME pointing at a JDK 17.
  log "Installing JDK 17 and the Android SDK command-line tools"
  brew install openjdk@17
  brew install --cask android-commandlinetools

  export JAVA_HOME="$(brew --prefix openjdk@17)/libexec/openjdk.jdk/Contents/Home"
  install_android_sdk "$(brew --prefix)/share/android-commandlinetools"
  log "  export JAVA_HOME=\"$JAVA_HOME\""
fi

log "Done. To build the fuzzer, point CC/CXX at LLVM's clang:"
log "  CC=\"\$(brew --prefix llvm)/bin/clang\" \\"
log "  CXX=\"\$(brew --prefix llvm)/bin/clang++\" scripts/fuzz.sh"
