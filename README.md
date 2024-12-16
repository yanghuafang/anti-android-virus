# anti-android-virus (aav) — Android malware static detection engine

[![CI](https://github.com/yanghuafang/anti-android-virus/actions/workflows/ci.yml/badge.svg)](https://github.com/yanghuafang/anti-android-virus/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)

`aav` (short for **Anti-Android-Virus**) is a **static** (non-emulating)
detection engine for Android malware. It
parses DEX bytecode (and the `classes.dex` inside an APK) and matches it against
a compact, multi-dimensional **signature database** — class-path signatures,
opcode-sequence and string/operand-sequence CRCs, an opcode bitmap pre-filter,
and AND/OR/XOR/NOT logic combinations — to decide whether a file is malicious
and, if so, which family it belongs to.

Its detection method comes from the Master of Engineering thesis *"An Efficient
Android Malware Static Detection System"* — [`docs/Thesis.md`](docs/Thesis.md)
gives the full method, algorithms, architecture and evaluation, and
[`docs/Architecture.md`](docs/Architecture.md) shows how the design maps onto the
code.

> **Status:** research / educational. The bundled sample database only detects a
> synthetic sample produced by `sigtool`; it is not a real-world malware feed.

---

## Why this project

|  |  |
|---|---|
| **Static, no emulation** | Detects malware by parsing DEX bytecode and matching signatures — no sandbox, no execution — so it is fast and safe to run on untrusted input. |
| **Multi-dimensional detection** | Combines class-path signatures, opcode- and string-sequence CRCs, an opcode bitmap pre-filter, and AND/OR/XOR/NOT logic — not one brittle heuristic. |
| **One abstraction, files *and* memory** | A small `IStream` / `ITarget` hierarchy lets the *same* scanners run on a file on disk **or** a block in RAM (`Scan` vs `ScanBuffer`) — ideal for on-device *and* gateway scanning. See [docs/ObjectModel.md](docs/ObjectModel.md). |
| **A real, ABI-clean SDK** | The whole engine is driven by one namespaced facade (`aav::IEngine`) that crosses the boundary with only PODs, C strings and a callback, so a prebuilt `libaav.so` stays compatible across compilers. |
| **Self-contained & tested** | `sigtool` generates a consistent sample DB + DEX, so it builds, runs, and tests end-to-end with no external assets; fuzzed under ASan/UBSan and CI'd on Linux, macOS, and Android. |
| **Grounded in a thesis** | Implements the method from the Master of Engineering thesis *"An Efficient Android Malware Static Detection System"* ([docs/Thesis.md](docs/Thesis.md)) — a compact, readable codebase for studying and extending that design. |

## How it works

```
file or directory
  │  FileID: DEX, ZIP/APK, or unknown?  (from magic)
  ▼
┌── ZIP/APK ─► ApkScanner: unpack classes*.dex (miniz), scan each ─┐
│                                                                  │
└── DEX ───────────────────────────────────────────► DexScanner ◄─┘
                                                          │
   DexFile   parse header, id tables, classes, methods, code items
                                                          │
   DexCode   per method: opcode buffer + operand/string buffer (+ CRC32s)
                                                          │
   opcode bitmap pre-filter ─► DexSigMgr: path / opcode-CRC / operand-CRC
                               + AND/OR/XOR/NOT logic ─► matched sig IDs
                                                          │
                                                          ▼
                     ScanReport (path, is_malware, sig IDs + names)
```

The engine takes a file or an in-memory image, identifies it, and — for a DEX or
the `classes*.dex` inside an APK — reduces each method to compact **features**
(class path, opcode sequence, referenced strings) that it matches against the
signature database. That matching is engineered to be cheap: an Aho–Corasick trie
over path-segment CRCs, binary search over sorted code-CRC tables, and an opcode
**bitmap** that skips methods no signature could match keep a whole-file scan
close to **O(n · log S)** (for *n* methods and *S* signatures) instead of the
O(n · S) of linear matchers — the source of the speed reported in
[docs/Benchmarks.md](docs/Benchmarks.md). Full walkthrough:
[docs/Architecture.md](docs/Architecture.md); the interface hierarchy that makes
files and memory interchangeable is in [docs/ObjectModel.md](docs/ObjectModel.md).

## Features

- **DEX static analysis** — a hardened, bounds-checked DEX parser (fuzzed under
  ASan/UBSan) that walks classes, methods and code items. Handles DEX versions
  `035`–`040` (Android 1.0 through 10+), including the modern method-handle /
  invoke-custom opcodes (DEX 038/039).
- **Multi-dimensional matching**
  - class-path signatures via an Aho–Corasick trie over per-segment CRC32s;
  - an opcode **bitmap** pre-filter to skip irrelevant methods cheaply;
  - opcode-sequence and operand(string)-sequence **CRC** signatures;
  - **logic combinations** (AND/OR/XOR/NOT) over code CRCs to confirm a hit.
- **APK support** — extracts every multidex member (`classes.dex`,
  `classes2.dex`, …) from the zip container (via vendored miniz), scans them all
  and merges the hits.
- **Self-contained tooling** — `sigtool` synthesizes a consistent sample DEX and
  a matching encrypted/compressed signature DB, so the whole pipeline runs and
  tests end-to-end with no external assets.
- **Modern C++17** — RAII ownership (`aav::ObjPtr`), factory functions, no
  hand-rolled reference counting, cross-platform on Linux, macOS, and Android.

## Requirements

- CMake ≥ 3.20
- A C++17 compiler (GCC ≥ 9, Clang ≥ 10, or Apple Clang)
- zlib (`zlib1g-dev` on Debian/Ubuntu; preinstalled on macOS)
- *(optional)* Clang with the libFuzzer + sanitizer runtimes, to build the fuzzers

APK/zip support (miniz) is vendored under `third_party/` — no extra dependency.

Install everything (compilers, CMake, zlib, `clang-format`, `gcovr`, LLVM) in one
step: `scripts/install-deps-ubuntu.sh` (Debian/Ubuntu) or
`scripts/install-deps-macos.sh` (macOS).

## Quick start

```bash
# 1. Configure + build (Debug, with the unit/e2e tests enabled)
cmake --preset debug -DAAV_BUILD_TESTS=ON
cmake --build build/debug -j

# 2. Generate a self-consistent sample DEX + signature DB
./build/debug/bin/sigtool gen-sample samples

# 3. Scan the sample: <signature-db> <apk|dex file|dir>
./build/debug/bin/aavscan samples/sample.sig samples/sample.dex
```

Expected output:

```
file: samples/sample.dex
  isMalware: 1  isWhite: 0
  sigID: 1002  Trojan!SampleFam.a@Android.Dex
  sigID: 1001  Trojan!SampleFam.a@Android.Dex
scanned 1 file(s), 1 flagged, 0.000s
```

`aavscan` accepts a single file or a directory (it walks the directory and scans
every `*.apk` / `*.dex` it finds), plus a few optional runtime flags:

- `--debug` — verbose engine diagnostics (stderr on host, logcat on Android),
  off by default so real-time scanning stays fast.
- `--analysis` — after scanning, print every method's opcode/operand CRC32s and
  referenced strings. This is the data used to author new signatures; off by
  default because it records every method (no bitmap pre-filter), so it is
  slower.
- `--mt <threads>` — scan a directory across `<threads>` worker threads (default
  `1` = sequential). Only directory scans are parallelized; a single file is
  always scanned on the calling thread. Reports are still delivered one at a
  time, so output matches a sequential scan apart from ordering.

Full usage:
`aavscan [--debug] [--analysis] [--mt <threads>] <signature-db> <apk|dex file|dir>`.

## Embedding the engine

The engine is driven through one small facade, `aav/engine_interface.h` (plus
`aav/object_interface.h`, the `IObject::Destroy()` base). This is the **entire**
public API, and it is deliberately **ABI-clean**: only PODs, C strings and a
callback cross the boundary — no `std::` containers or smart pointers — so a
prebuilt `libaav.so` stays compatible across compiler/stdlib versions. File
identification, signature-DB loading, scanner selection, APK unpacking and
directory walking are all hidden behind it:

```cpp
#include "aav/engine_interface.h"

static void on_report(const aav::ScanReport* r, void* user) {
  if (r->is_malware) {
    // r->path, r->sig_ids[0..sig_count), r->names[...], and r->classes[...] when
    // analysis is enabled -- all engine-owned, valid only during this call.
  }
}

aav::IEngine* engine = aav::MakeEngine();
aav::EngineConfig config;  // scan_apk / scan_dex / recurse_dirs / verbose /
                           // analysis / scan_threads (>1 parallelizes dir scans)
engine->Init("samples/sample.sig", &config);

engine->Scan("path/to/file-or-dir", on_report, nullptr);  // file OR dir; APKs unpacked
// ...or scan an image already in RAM (no file on disk); apk/dex auto-detected:
engine->ScanBuffer(bytes, size, "app.apk", on_report, nullptr);

engine->Destroy();  // release the engine (never `delete` it)
```

Link against the engine with `target_link_libraries(app PRIVATE aav::aav)`
(static) or `aav::shared` (shared). See [Install / SDK](#install--sdk) to consume
it as a packaged SDK via `find_package(aav)`.

## Scripts

Prefer one-liners? [`scripts/`](scripts/) wraps the commands above:

```bash
scripts/build.sh     # configure + build (engine, aavscan, sigtool)
scripts/test.sh      # build + unit + e2e tests
scripts/run.sh       # generate a sample and scan it end-to-end
scripts/asan.sh      # sanitizer build + tests
scripts/format.sh    # clang-format check (--fix to apply)
```

See [`scripts/README.md`](scripts/README.md) for the full set (fuzzing, Android, clean).

## Build options

| Option              | Default | Description                                    |
| ------------------- | ------- | ---------------------------------------------- |
| `AAV_BUILD_TOOLS`   | `ON`    | Build `sigtool` (sample/DB generator)          |
| `AAV_BUILD_TESTS`   | `OFF`   | Build unit tests + register the CTest suite    |
| `AAV_BUILD_FUZZERS` | `OFF`   | Build the libFuzzer harness(es) (Clang only)   |
| `AAV_ENABLE_APK`    | `ON`    | APK/zip scanning via vendored miniz            |
| `AAV_BUILD_SHARED`  | `ON`    | Build the shared library (`libaav.so`/`.dylib`)|
| `AAV_ENABLE_COVERAGE` | `OFF` | Instrument for gcovr line/branch coverage      |
| `AAV_INSTALL`       | `ON`\*  | Generate SDK install rules (\*top-level only)  |

Configure presets (`CMakePresets.json`): `debug`, `release`, `asan`, `coverage`,
`fuzz`.

## Install / SDK

The engine ships as an SDK — public headers plus a static **and** a shared
library — installable to any prefix:

```bash
cmake --preset release && cmake --build build/release -j
cmake --install build/release --prefix /path/to/sdk
```

which lays out:

```
/path/to/sdk/
├── include/aav/      # public headers: engine_interface.h, object_interface.h, aav.h
└── lib/
    ├── libaav.a                   # static
    ├── libaav.so / libaav.dylib   # shared (self-contained: miniz built in)
    └── cmake/aav/                 # find_package(aav) config
```

Consume it from another CMake project:

```cmake
find_package(aav REQUIRED)
target_link_libraries(myapp PRIVATE aav::aav)     # static
# or:  target_link_libraries(myapp PRIVATE aav::shared)
```

## Testing

```bash
# Unit + end-to-end tests
cmake --preset debug -DAAV_BUILD_TESTS=ON && cmake --build build/debug -j
ctest --test-dir build/debug --output-on-failure

# AddressSanitizer + UndefinedBehaviorSanitizer
cmake --preset asan -DAAV_BUILD_TESTS=ON && cmake --build build/asan -j
ctest --test-dir build/asan --output-on-failure
```

Fuzzing the DEX parser (requires a Clang toolchain with libFuzzer):

```bash
cmake --preset fuzz -DCMAKE_CXX_COMPILER=clang++
cmake --build build/fuzz --target fuzz_dexfile -j
./build/fuzz/bin/fuzz_dexfile -max_total_time=60
```

CI (GitHub Actions) covers the three supported platforms — **Ubuntu 24.04 / 26.04
(x86_64)** (GCC + Clang) and **macOS (ARM64)** build + test, and a **Android
(ARM64, arm64-v8a)** NDK cross-compile. It also runs the ASan/UBSan suite, checks
formatting, and smoke-runs the fuzzer on Linux.

## Project layout

```
.
├── CMakeLists.txt            # root: options, deps, install; delegates to subdirs
├── CMakePresets.json         # debug / release / asan / coverage / fuzz presets
├── include/aav/              # public SDK: engine_interface.h + object_interface.h + aav.h
├── src/
│   ├── engine/               # the IEngine facade implementation
│   ├── api/aav/              # internal object API (interfaces, factories, data records) — not exported
│   ├── platform/             # file/memory primitives (FileStream, FileTarget, FileMap, MemTarget)
│   ├── utils/                # crc32, leb128, blowfish, gzip inflate, logger
│   ├── sig/                  # signature-DB load/decrypt/decompress, format
│   ├── dex/                  # DEX parser + path/opcode/operand/logic matchers
│   └── scan/                 # file-type id (FileID) + APK (zip) white-list check
├── apps/
│   ├── aavscan/              # CLI scanner (thin facade consumer)
│   └── sigtool/              # sample DEX + signature-DB generator
├── android/                  # Gradle + NDK app; JNI bridge over the engine
├── tests/
│   ├── unit/                 # doctest white-box unit tests (one binary)
│   └── e2e/                  # generate-and-scan end-to-end CTest drivers
├── fuzz/                     # libFuzzer harness for the DEX parser
├── third_party/             # vendored: miniz (zip), doctest
└── docs/                     # guides — see docs/README.md for the index
```

## Documentation

Full index: [`docs/README.md`](docs/README.md).

| Guide | Topics |
|-------|--------|
| [Thesis.md](docs/Thesis.md) | Full English thesis (method, algorithms, architecture, evaluation), rewritten to match this code |
| [Architecture.md](docs/Architecture.md) | Scan pipeline, engine components, thesis→code mapping |
| [ObjectModel.md](docs/ObjectModel.md) | Interface hierarchy, file-vs-memory abstraction, RAII, namespacing |
| [Building.md](docs/Building.md) | Build options, install/SDK, testing, sanitizers, fuzzing, Android |
| [Signatures.md](docs/Signatures.md) | Authoring signatures with `sigtool` / `aavscan --analysis` |
| [SignatureDbFormat.md](docs/SignatureDbFormat.md) | On-disk `*.sig` signature-database binary format |
| [Benchmarks.md](docs/Benchmarks.md) | Detection / FPR / scan-speed results (thesis Ch. 5), vs. Antiy AVL SDK and 360 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Build, test, and pull-request workflow |

## Android

The core engine (`libaav`) and the `aavscan` CLI **cross-compile for Android**
via the NDK; CI builds the arm64-v8a (ARM64) ABI on every change:

```bash
cmake -S . -B build/android \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 \
  -DAAV_BUILD_CLI=OFF -DAAV_BUILD_TOOLS=OFF -DAAV_BUILD_TESTS=OFF
cmake --build build/android -j
```

A demo **Android app** (`com.av.aav`) that drives the engine on-device via JNI
lives under [`android/`](android/README.md); its JNI bridge is a consumer of the
public `IEngine` SDK facade and statically links `libaav` (no separate engine
`.so`). Build it with
`cd android && ./gradlew :app:assembleDebug` (SDK 36 / NDK 29 / JDK 17); CI
assembles the debug APK on every change.

## Contributing

Contributions are welcome — parser hardening, new tests, docs, opcode/version
support, and engine features. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for
the build / test / coding-style workflow, and run `scripts/test.sh` and
`scripts/asan.sh` before opening a pull request.

## License

Licensed under the MIT License — see [`LICENSE`](LICENSE).
