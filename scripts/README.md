# Dev scripts

Thin wrappers around the CMake / CTest / NDK / Gradle commands used in CI, so the
common tasks are a single line. Every script resolves the repo root itself (so it
works from any directory), honours `CC` / `CXX`, and forwards extra arguments to
the underlying `cmake` invocation.

The build/test scripts are wrappers around `CMakePresets.json`, not a second way
to configure the project: `build.sh` is `cmake --preset $PRESET`, `test.sh` adds
`ctest --preset $PRESET`, and CI runs those same presets. So a red CI job
reproduces with the command it ran, and a flag that matters lives in the preset
where both can see it.

Nothing is written inside the checkout: every script builds into `$AAV_BUILD_ROOT`,
the sibling `../anti-android-virus-build/` that `common.sh` derives. Set that
variable to build somewhere else.

The three check scripts — `format.sh`, `tidy.sh`, `docs.sh` — are each their own
CI job and each fails the build, so running them locally is what keeps a pull
request green. Both print the binary and version they used, because diagnostics
move between clang majors.

`format.sh` additionally pins: it takes clang-format at
`$AAV_CLANG_FORMAT_VERSION` (`common.sh`, currently 18, matching the CI runner)
and warns when it cannot find it, because formatting is a hard gate and an
unpinned formatter is how a clean local run becomes a red pull request.
`tidy.sh` does not pin — clang-tidy compiles each file, so it has to be new
enough for the host's standard library, and an old one fails to parse a current
macOS SDK rather than reporting on this project. On macOS both come from
Homebrew's keg-only `llvm` / `llvm@18`, because Xcode ships neither.

| Script | What it does |
| --- | --- |
| `install-deps-ubuntu.sh` | Install the full build/test toolchain on Debian/Ubuntu (apt); `--android` adds the SDK/NDK + JDK 17, `--docs-only` trims to Doxygen + graphviz. |
| `install-deps-macos.sh` | Install the full build/test toolchain on macOS (Homebrew); `--android` adds the SDK/NDK + JDK 17. |
| `build.sh` | Configure + build the engine, `aavscan`, and `sigtool` (`PRESET`, default `debug`). |
| `test.sh` | Build, then run the unit + e2e CTest suites (`PRESET`, default `debug`). |
| `asan.sh` | Build + test under AddressSanitizer + UBSan (the `asan` preset). |
| `tsan.sh` | Build + test under ThreadSanitizer (the `tsan` preset). Separate from `asan.sh` because the two runtimes cannot share a binary. |
| `coverage.sh` | Build + test with coverage (the `coverage` preset), then report line/branch coverage via `gcovr` (`--html` for a browsable report). |
| `run.sh` | Generate a sample DEX + signature DB with `sigtool` and scan it with `aavscan`. |
| `fuzz.sh` | Build and run the libFuzzer DEX harness (needs a Clang with libFuzzer); `--build-only` stops after the build, which is the half CI gates on. |
| `format.sh` | `clang-format` check over the tracked sources; `--fix` to rewrite. |
| `tidy.sh` | `clang-tidy` check over the sources the build compiled; `--fix` applies what it can. |
| `docs.sh` | Build the Doxygen API reference into `<build root>/docs/html`; `--open` shows it. |
| `android.sh` | Cross-compile the engine + CLI for Android via the NDK. |
| `android-app.sh` | Assemble the sample Android app (`gradlew :app:assembleDebug`). |
| `clean.sh` | Remove the build root and generated sample data. |
| `remote-ubuntu.sh` | Run any of these on the Ubuntu box, optionally syncing the tree first. |

## Examples

```bash
scripts/install-deps-ubuntu.sh        # one-time toolchain setup (Debian/Ubuntu)
scripts/build.sh                      # Debug build (the `debug` preset)
PRESET=release scripts/build.sh       # Release build
scripts/test.sh                       # build + unit + e2e tests
PRESET=release scripts/test.sh        # the same suite with -O2 and no asserts
scripts/asan.sh                       # ASan + UBSan build + tests
scripts/tsan.sh                       # ThreadSanitizer build + tests
scripts/coverage.sh                   # coverage report; fails under 65% by default
scripts/run.sh                        # end-to-end sample scan
scripts/run.sh path/to/app.apk        # scan your own APK/DEX (uses the sample DB)
scripts/format.sh --fix               # reformat sources in place
scripts/tidy.sh                       # clang-tidy check (--fix to apply)
scripts/docs.sh --open                # build + open the API reference
ABI=x86_64 scripts/android.sh         # NDK cross-compile for x86_64
FUZZ_TIME=60 scripts/fuzz.sh          # fuzz for 60s (Clang + libFuzzer)
scripts/install-deps-macos.sh --android     # + Android SDK/NDK and a JDK
(cd scripts && ./remote-ubuntu.sh --sync ./asan.sh)  # ASan on Linux, from scripts/
```

## Running on Linux from a Mac

`remote-ubuntu.sh` exists because part of CI is unreachable from macOS:
LeakSanitizer rides along with ASan on Linux only, `coverage.sh`'s gate is
measured against gcc/gcov, `fuzz.sh` uses the distro clang's libFuzzer, and
`install-deps-ubuntu.sh` is Debian-only. It runs a command on the Ubuntu host,
with `--sync` to mirror the working tree (uncommitted edits included) or
`--clone` to fetch what was pushed.

Unlike the others, it is run from this directory, and the command it forwards
runs in the remote `scripts/` — so a sibling is just `./asan.sh`, whether it is
sent as an argv or as `--shell` text. A probe about the checkout as a whole
starts with a `cd`: `--shell 'cd .. && git log -1'`.

```bash
cd scripts
./remote-ubuntu.sh --sync            # mirror this tree to the host, then stop
./remote-ubuntu.sh ./test.sh         # build + test there
./remote-ubuntu.sh --sync ./asan.sh  # mirror, then ASan + UBSan on Linux
./remote-ubuntu.sh --shell './test.sh | tail -3'   # shell text, not an argv
```

See the script header for the rest.
