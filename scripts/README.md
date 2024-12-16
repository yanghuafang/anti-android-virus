# Dev scripts

Thin wrappers around the CMake / CTest / NDK / Gradle commands used in CI, so the
common tasks are a single line. Every script resolves the repo root itself (so it
works from any directory), honours `CC` / `CXX`, and forwards extra arguments to
the underlying `cmake` invocation.

| Script | What it does |
| --- | --- |
| `install-deps-ubuntu.sh` | Install the full build/test toolchain on Debian/Ubuntu (apt). |
| `install-deps-macos.sh` | Install the full build/test toolchain on macOS (Homebrew). |
| `build.sh` | Configure + build the engine, `aavscan`, and `sigtool` (host). |
| `test.sh` | Build with tests enabled, then run the unit + e2e CTest suites. |
| `asan.sh` | Build + test under AddressSanitizer + UBSan (the `asan` preset). |
| `coverage.sh` | Build + test with coverage (the `coverage` preset), then report line/branch coverage via `gcovr` (`--html` for a browsable report). |
| `run.sh` | Generate a sample DEX + signature DB with `sigtool` and scan it with `aavscan`. |
| `fuzz.sh` | Build and run the libFuzzer DEX harness (needs a Clang with libFuzzer). |
| `format.sh` | `clang-format` check over the tracked sources; `--fix` to rewrite. |
| `android.sh` | Cross-compile the engine + CLI for Android via the NDK. |
| `android-app.sh` | Assemble the sample Android app (`gradlew :app:assembleDebug`). |
| `clean.sh` | Remove `build/` and generated sample data. |

## Examples

```bash
scripts/install-deps-ubuntu.sh        # one-time toolchain setup (Debian/Ubuntu)
scripts/build.sh                      # Debug build
BUILD_TYPE=Release scripts/build.sh   # Release build
scripts/test.sh                       # build + unit + e2e tests
scripts/asan.sh                       # sanitizer build + tests
COVERAGE_FAIL_UNDER=65 scripts/coverage.sh  # coverage report, fail under 65%
scripts/run.sh                        # end-to-end sample scan
scripts/run.sh path/to/app.apk        # scan your own APK/DEX (uses the sample DB)
scripts/format.sh --fix               # reformat sources in place
ABI=x86_64 scripts/android.sh         # NDK cross-compile for x86_64
FUZZ_TIME=60 scripts/fuzz.sh          # fuzz for 60s (Clang + libFuzzer)
```
