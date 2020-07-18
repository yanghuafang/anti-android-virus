# Building, testing & packaging

## Requirements

- CMake ≥ 3.21 (set by `CMakePresets.json` schema v3; see below)
- A C++17 compiler (GCC ≥ 9, Clang ≥ 10, or Apple Clang)
- zlib (`zlib1g-dev` on Debian/Ubuntu; preinstalled on macOS)
- *(optional)* Clang with libFuzzer + sanitizer runtimes, to build the fuzzers
- *(checks)* `clang-format`, `clang-tidy`, `gcovr`, `doxygen` + `graphviz`

`scripts/format.sh` and `scripts/tidy.sh` print the binary and version they
used, because layout and check diagnostics move between clang majors. On macOS
they take both tools from Homebrew's keg-only `llvm` — Xcode ships neither.

The 3.21 floor is two separate requirements, of which the larger wins:

| Requirement | Needs | Set by |
|---|---|---|
| Newest command used in the `CMakeLists.txt` | 3.13 | `target_link_options` |
| `CMakePresets.json` schema version | 3.21 | schema v3 |

So the build code itself would run on 3.13; `CMakePresets.json` alone raises
the floor to 3.21. Schema v3 is what lets a preset omit `generator` and inherit
the platform default — on v2 (3.20) that field is required, so every preset
would have to hard-code Ninja or Makefiles. Dropping presets is what lowering
the floor would cost.

APK/zip support (miniz) and the unit-test framework (doctest) are vendored under
`third_party/` — no extra dependencies.

Install the whole toolchain (compilers, CMake, zlib, the check tools, and — on
macOS — LLVM for libFuzzer) in one step:

```bash
scripts/install-deps-ubuntu.sh   # Debian/Ubuntu (apt)
scripts/install-deps-macos.sh    # macOS (Homebrew; needs Xcode CLT + brew)
```

The Android SDK and NDK are opt-in — pass `--android` to either script. That
adds a JDK 17 (Gradle needs one; nothing else here does) and the SDK
command-line tools, then installs the versions pinned in
[`scripts/android-sdk-packages.txt`](../scripts/android-sdk-packages.txt) with
`sdkmanager`. The script prints the `ANDROID_HOME` / `ANDROID_NDK_HOME` /
`JAVA_HOME` exports to add to your profile.

Both platforms converge on `sdkmanager` deliberately. A standalone NDK — the
`android-ndk` Homebrew cask, or apt's `google-android-ndk-*-installer` — is
enough for `scripts/android.sh`, which only reads `$ANDROID_NDK_HOME`, but not
for the app: AGP resolves the `ndkVersion` pin from `$ANDROID_HOME/ndk/<version>`
and accepts nothing else.

## Build

```bash
cmake --preset debug -DAAV_BUILD_TESTS=ON
cmake --build ../anti-android-virus-build/debug -j
```

Configure presets (`CMakePresets.json`): `debug`, `release`, `asan`, `coverage`,
`fuzz`. The [`scripts/`](../scripts/) helpers (`build.sh`, `test.sh`, `asan.sh`,
`coverage.sh`, `fuzz.sh`, …) wrap these presets so the build flags live in one
place.

### Where output goes

Nothing generated is written inside the checkout. Every build tree — the CMake
presets, the NDK cross-builds, the Gradle projects and their cache, the Doxygen
site — lands in a sibling directory of the repository:

```
anti-android-virus/            the checkout: tracked files only
anti-android-virus-build/
  debug/ release/ asan/ …      CMake trees, one per preset
  android-<abi>/               NDK cross-build (scripts/android.sh)
  gradle/app/                  the sample app, APKs under outputs/apk/
  gradle-cache/  cxx/          Gradle project cache, NDK CMake staging
  docs/html/                   Doxygen site (scripts/docs.sh)
```

`scripts/clean.sh` removes the whole directory. To build somewhere else, set
`AAV_BUILD_ROOT` for the scripts, `-B <dir>` for a hand-written CMake configure,
and `-PaavBuildRoot=<dir>` for Gradle.

`AAV_BUILD_ROOT` moves the NDK, Gradle and Doxygen output but not the preset
trees: a CMake preset cannot read an environment variable with a fallback, so
`binaryDir` is anchored to the source directory and `cmake --preset debug` would
break if it were not. The scripts follow the same split — `$AAV_PRESET_ROOT` in
`common.sh` is what they use to name a tree CMake configured. Moving the preset
trees means editing `CMakePresets.json` and that variable together.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `AAV_BUILD_TOOLS` | `ON` | Build `sigtool` (sample / DB generator) |
| `AAV_BUILD_TESTS` | `OFF` | Build unit tests + register the CTest suite |
| `AAV_BUILD_FUZZERS` | `OFF` | Build the libFuzzer harness(es) (Clang only) |
| `AAV_ENABLE_APK` | `ON` | APK/zip scanning via vendored miniz |
| `AAV_BUILD_SHARED` | `ON` | Build the shared library (`libaav.so` / `.dylib`) |
| `AAV_ENABLE_COVERAGE` | `OFF` | Instrument for gcovr line/branch coverage (`--coverage`) |
| `AAV_ENABLE_ASAN` | `OFF` | Instrument with ASan + UBSan (the `asan` preset sets this) |
| `AAV_ENABLE_TSAN` | `OFF` | Instrument with ThreadSanitizer (the `tsan` preset sets this). Mutually exclusive with `AAV_ENABLE_ASAN`: the two runtimes cannot share a binary, and CMake refuses the combination |
| `AAV_INSTALL` | `ON`\* | Generate SDK install rules (\*top-level build only) |

## Testing

```bash
cmake --preset debug -DAAV_BUILD_TESTS=ON && cmake --build ../anti-android-virus-build/debug -j
ctest --test-dir ../anti-android-virus-build/debug --output-on-failure
```

Suites: `unit` (doctest white-box tests, including a 3000-iteration
random-DEX fuzz-like test), and the end-to-end drivers `e2e_sample` /
`e2e_memscan` / `e2e_multidex` / `e2e_multithread` (generate a sample with
`sigtool`, then scan a file, an in-memory buffer, a multidex APK, and a
directory via `aavscan --mt` / the mem checker, asserting the signatures fire).

### Sanitizers

```bash
cmake --preset asan -DAAV_BUILD_TESTS=ON && cmake --build ../anti-android-virus-build/asan -j
ctest --test-dir ../anti-android-virus-build/asan --output-on-failure
```

### Fuzzing (the DEX parser)

```bash
cmake --preset fuzz -DCMAKE_CXX_COMPILER=clang++
cmake --build ../anti-android-virus-build/fuzz --target fuzz_dexfile -j
../anti-android-virus-build/fuzz/bin/fuzz_dexfile -max_total_time=60
```

## Install / SDK

```bash
cmake --preset release && cmake --build ../anti-android-virus-build/release -j
cmake --install ../anti-android-virus-build/release --prefix /path/to/sdk
```

Layout:

```
/path/to/sdk/
├── include/aav/    # engine_interface.h, object_interface.h, aav.h
└── lib/
    ├── libaav.a                 # static
    ├── libaav.so / .dylib       # shared (miniz built in)
    └── cmake/aav/               # find_package(aav) config
```

Consume it from another CMake project:

```cmake
find_package(aav REQUIRED)
target_link_libraries(myapp PRIVATE aav::aav)   # or aav::shared
```

## Android / cross-compile

```bash
cmake -S . -B ../anti-android-virus-build/android \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 \
  -DAAV_BUILD_TOOLS=OFF -DAAV_BUILD_TESTS=OFF
cmake --build ../anti-android-virus-build/android -j
```

The demo app + JNI bridge live under [`../android/`](../android/README.md).

## Checks

Three scripts, each its own CI job and each a gate:

```bash
scripts/format.sh    # clang-format over the tracked sources (--fix to rewrite)
scripts/tidy.sh      # clang-tidy over what the build compiled (--fix applies)
scripts/docs.sh      # Doxygen API reference into <build root>/docs (--open shows it)
```

`tidy.sh` takes its file list from `compile_commands.json`, not from `find`,
and errors if a file it was asked about is missing from it — a source added
without re-running CMake would otherwise be skipped silently. `docs.sh` gates on
Doxygen's warning log, not its exit status, because Doxygen exits 0 after
complaining about a broken reference.

The check list is [`../.clang-tidy`](../.clang-tidy). The tree follows the
[Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html), so
the whole `google-*` family is on and enforced clean, plus the few checks
covering rules the guide states that `google-*` does not implement. Each family
left out records why. Scope is style and redundancy; bug-hunting belongs to the
sanitizer build and the fuzzer above, which execute the code.

## CI

GitHub Actions covers the three supported platforms — **Linux (x86_64)** (GCC +
Clang), **macOS (ARM64)**, and an **Android (arm64-v8a)** NDK cross-compile —
plus the ASan/UBSan suite, a gcovr coverage floor, the three check jobs above,
a fuzz smoke run, and the Android app APK assembly.

Every job is a gate except the fuzz smoke run. That one is `continue-on-error`
on purpose: a seedless 30-second run explores different input each time, so
gating on it would fail pull requests for findings they did not introduce. The
fuzzer *build* is still a gate. A separate `docs.yml` workflow publishes the API
reference to GitHub Pages on every push to `main`; nothing generated is
committed.
