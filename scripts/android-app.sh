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
APP_BUILD="$AAV_BUILD_ROOT/gradle/app"

# build.gradle moves the per-project build directories to $AAV_BUILD_ROOT;
# --project-cache-dir moves Gradle's own cache, which no build file can set.
log "./gradlew $TASK"
./gradlew --project-cache-dir "$AAV_BUILD_ROOT/gradle-cache" "$TASK" "$@"

log "APK(s) under $APP_BUILD/outputs/apk/"
