# Building, testing & packaging

## Requirements

- CMake ≥ 3.20
- A C++17 compiler (GCC ≥ 9, Clang ≥ 10, or Apple Clang)
- zlib (`zlib1g-dev` on Debian/Ubuntu; preinstalled on macOS)
- *(optional)* Clang with libFuzzer + sanitizer runtimes, to build the fuzzers

APK/zip support (miniz) and the unit-test framework (doctest) are vendored under
`third_party/` — no extra dependencies.

Install the whole toolchain (compilers, CMake, zlib, `clang-format`, `gcovr`,
and — on macOS — LLVM for libFuzzer) in one step:

```bash
scripts/install-deps-ubuntu.sh   # Debian/Ubuntu (apt)
scripts/install-deps-macos.sh    # macOS (Homebrew; needs Xcode CLT + brew)
```

The Android NDK is separate — install it via Android Studio or
`sdkmanager "ndk;<version>"`.

## Build

```bash
cmake --preset debug -DAAV_BUILD_TESTS=ON
cmake --build build/debug -j
```

Configure presets (`CMakePresets.json`): `debug`, `release`, `asan`, `coverage`,
`fuzz`. The [`scripts/`](../scripts/) helpers (`build.sh`, `test.sh`, `asan.sh`,
`coverage.sh`, `fuzz.sh`, …) wrap these presets so the build flags live in one
place.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `AAV_BUILD_TOOLS` | `ON` | Build `sigtool` (sample / DB generator) |
| `AAV_BUILD_TESTS` | `OFF` | Build unit tests + register the CTest suite |
| `AAV_BUILD_FUZZERS` | `OFF` | Build the libFuzzer harness(es) (Clang only) |
| `AAV_ENABLE_APK` | `ON` | APK/zip scanning via vendored miniz |
| `AAV_BUILD_SHARED` | `ON` | Build the shared library (`libaav.so` / `.dylib`) |
| `AAV_ENABLE_COVERAGE` | `OFF` | Instrument for gcovr line/branch coverage (`--coverage`) |
| `AAV_INSTALL` | `ON`\* | Generate SDK install rules (\*top-level build only) |

## Testing

```bash
cmake --preset debug -DAAV_BUILD_TESTS=ON && cmake --build build/debug -j
ctest --test-dir build/debug --output-on-failure
```

Suites: `unit` (doctest white-box tests, including a 3000-iteration
random-DEX fuzz-like test), and the end-to-end drivers `e2e_sample` /
`e2e_memscan` / `e2e_multidex` / `e2e_multithread` (generate a sample with
`sigtool`, then scan a file, an in-memory buffer, a multidex APK, and a
directory via `aavscan --mt` / the mem checker, asserting the signatures fire).

### Sanitizers

```bash
cmake --preset asan -DAAV_BUILD_TESTS=ON && cmake --build build/asan -j
ctest --test-dir build/asan --output-on-failure
```

### Fuzzing (the DEX parser)

```bash
cmake --preset fuzz -DCMAKE_CXX_COMPILER=clang++
cmake --build build/fuzz --target fuzz_dexfile -j
./build/fuzz/bin/fuzz_dexfile -max_total_time=60
```

## Install / SDK

```bash
cmake --preset release && cmake --build build/release -j
cmake --install build/release --prefix /path/to/sdk
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
cmake -S . -B build/android \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 \
  -DAAV_BUILD_TOOLS=OFF -DAAV_BUILD_TESTS=OFF
cmake --build build/android -j
```

The demo app + JNI bridge live under [`../android/`](../android/README.md).

## CI

GitHub Actions covers the three supported platforms — **Ubuntu 24.04 / 26.04
(x86_64)** (GCC + Clang), **macOS (ARM64)**, and an **Android (arm64-v8a)** NDK
cross-compile — plus the ASan/UBSan suite, a `clang-format` check, a fuzz smoke
run, and the Android app APK assembly.
