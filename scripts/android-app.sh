#!/usr/bin/env bash
# Assemble the sample Android app (Java UI + JNI bridge + engine for all ABIs).
#
#   scripts/android-app.sh [extra gradle args...]
#
# Env: GRADLE_TASK (default: :app:assembleDebug)
# Requires the Android SDK/NDK + JDK 17 — see android/README.md.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

cd "$AAV_ROOT/android"
TASK="${GRADLE_TASK:-:app:assembleDebug}"

log "./gradlew $TASK"
./gradlew "$TASK" "$@"

log "APK(s) under android/app/build/outputs/apk/"
