#!/usr/bin/env bash
# Cross-compile the engine (libaav.a) + aavscan CLI for Android via the NDK.
#
#   scripts/android.sh [extra cmake configure args...]
#
# Env:
#   ABI  arm64-v8a (default) | armeabi-v7a | x86_64 | x86
#   API  Android platform level (default: 24)
#   NDK path via ANDROID_NDK_LATEST_HOME / ANDROID_NDK_HOME / ANDROID_NDK_ROOT
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require cmake
ABI="${ABI:-arm64-v8a}"
API="${API:-24}"
NDK="${ANDROID_NDK_LATEST_HOME:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
[ -n "$NDK" ] || die "NDK path not set (export ANDROID_NDK_HOME=/path/to/ndk)"
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
[ -f "$TOOLCHAIN" ] || die "NDK toolchain not found: $TOOLCHAIN"

DIR="build/android-$ABI"
log "Configure  ABI=$ABI  API=$API  NDK=$NDK"
cmake -S "$AAV_ROOT" -B "$AAV_ROOT/$DIR" \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DANDROID_ABI="$ABI" \
  -DANDROID_PLATFORM="android-$API" \
  -DAAV_BUILD_TESTS=OFF -DAAV_BUILD_TOOLS=OFF \
  "$@"

log "Build"
cmake --build "$AAV_ROOT/$DIR" -j

log "Artifacts: $DIR/lib/libaav.a   $DIR/bin/aavscan"
