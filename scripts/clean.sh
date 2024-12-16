#!/usr/bin/env bash
# Remove build directories and generated sample data.
#
#   scripts/clean.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

cd "$AAV_ROOT"
log "Removing build/, generated samples, and Android build output"
rm -rf build
rm -f samples/sample.dex samples/sample.sig
rm -rf android/app/build android/.gradle
log "Clean."
