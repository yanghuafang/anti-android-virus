# anti-android-virus (aav) — Android malware static detection engine

[![Build](https://github.com/yanghuafang/anti-android-virus/actions/workflows/build.yml/badge.svg)](https://github.com/yanghuafang/anti-android-virus/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)

`aav` (short for **Anti-Android-Virus**) is a **static** (non-emulating)
detection engine for Android malware. It parses DEX bytecode and matches it
against a compact, multi-dimensional signature database — class-path
signatures, opcode-sequence and string/operand-sequence CRCs, an opcode bitmap
pre-filter, and AND/OR/XOR/NOT logic combinations — to decide whether a file is
malicious and, if so, which family it belongs to.

Static means no sandbox and no execution: scanning an untrusted APK costs a
parse rather than a process, which is what makes it usable on the device it is
protecting.

Its detection method comes from the Master of Engineering thesis *"An Efficient
Android Malware Static Detection System"* — [`docs/Thesis.md`](docs/Thesis.md)
gives the method, the algorithms, the architecture and the evaluation it was
measured by. The code that follows is that design, so the thesis is the place to
read *why* a scan is shaped the way it is.

> **Status:** early. This commit is the skeleton and the primitives every later
> layer needs; the DEX parser, the signature database and the scan engine land
> on top of them.

## The DEX front end

`DexFile` parses the container — header, id tables, class definitions, class
data — and hands out one class and then one method at a time. `DexCode` walks a
method's code item instruction by instruction and reduces it to two buffers: the
opcode sequence, and the constant operands (the strings a method references).
Those two buffers are what detection matches on, so the parser's job ends where
their CRC32s begin.

The parser is written from scratch and bounds-checks every offset it follows,
because the input is hostile by definition: malware deliberately emits DEX that
off-the-shelf tools mis-parse. Versions `035`–`040` are accepted, including the
method-handle and `invoke-custom` opcodes DEX 038/039 added.

## Matching class paths

The first detection dimension is the package path: whole families live under one
package, so `com.aav.sample.evil` classifies a class without looking at a single
instruction.

Matching is an Aho-Corasick trie, but keyed on the CRC32 of each dotted segment
rather than on characters. A path has a handful of segments and thousands of
signatures share prefixes, so one walk over the segments visits every candidate
at once instead of testing signatures one at a time. A hit is confirmed by
logic over the matched signature's parts — a package alone can be too broad, so
a signature can require several paths together.

## Matching method code

The second dimension is the method body. `DexCode` already reduces a method to
an opcode sequence and a constant-operand sequence; each becomes a CRC32, and a
signature is a CRC to find plus a boolean expression over CRCs —
AND/OR/XOR/NOT — that has to hold before the file is called malicious. One
fragment is rarely a behavior; a combination is.

Two things keep that cheap. The CRC tables are sorted and binary-searched, so a
lookup is logarithmic in the number of signatures. And ahead of them sits an
opcode **bitmap**: a method's first eight opcodes, packed pairwise, are tested
against a per-position allow-list, so a method no signature could match is
skipped before its CRCs are ever computed.

## Quick start

```bash
# 1. Configure + build (Debug, with the tests enabled)
cmake --preset debug
cmake --build ../anti-android-virus-build/debug -j

# 2. Generate a self-consistent sample DEX + signature DB
../anti-android-virus-build/debug/bin/sigtool gen-sample samples

# 3. Scan the sample: <signature-db> <apk|dex file or dir>
../anti-android-virus-build/debug/bin/aavscan samples/sample.sig samples/sample.dex
```

Expected output:

```
file: samples/sample.dex
  isMalware: 1  isWhite: 0
  sigID: 1002  Trojan!SampleFam.a@Android.Dex
  sigID: 1001  Trojan!SampleFam.a@Android.Dex
scanned 1 file(s), 1 flagged, 0.000s
```

`scripts/run.sh` is those three steps in one command.

`--analysis` prints, after the scan, every class the parser saw with its fields
and every method with its opcode/operand CRC32s and referenced strings. That is
the data a new signature is written from — see
[`docs/Signatures.md`](docs/Signatures.md). It is off by default because it
records every method, which means bypassing the bitmap pre-filter that makes a
normal scan fast.

`aavscan` also takes a directory and walks it, scanning every `*.apk` / `*.dex`
it finds. `--mt <threads>` spreads that walk across worker threads; a single
file is always scanned on the calling thread, and reports still arrive one at a
time, so the output matches a sequential scan apart from ordering.

`sigtool` exists because a detection engine is untestable without detection
data, and a real malware database cannot be checked into a public repository.
It synthesizes a DEX and the signature database that matches it, from one
generator the unit tests reuse — so the fixtures and the tool cannot drift, and
the whole pipeline runs with no external assets. The on-disk format the tool
writes is documented in
[`docs/SignatureDbFormat.md`](docs/SignatureDbFormat.md).

## Embedding the engine

The whole pipeline is driven through one facade, `aav/engine_interface.h` (plus
`aav/object_interface.h`, the `IObject::Destroy()` base). That is the entire
public API, and it is deliberately ABI-clean: only PODs, C strings and a
callback cross the boundary — no `std::` containers or smart pointers — so a
prebuilt library stays usable across compiler and stdlib versions. File
identification, signature-DB loading, scanner selection and directory walking
all sit behind it:

```cpp
#include "aav/engine_interface.h"

static void on_report(const aav::ScanReport* r, void* user) {
  if (r->is_malware) {
    // r->path, r->sig_ids[0..sig_count), r->names[...], and r->classes[...]
    // when analysis is enabled -- all engine-owned, valid only during this
    // call.
  }
}

aav::IEngine* engine = aav::MakeEngine();
aav::EngineConfig config;   // scan_apk / scan_dex / recurse_dirs / verbose /
                            // analysis / scan_threads (>1 parallelizes dirs)
engine->Init("samples/sample.sig", &config);
engine->Scan("path/to/file-or-dir", on_report, nullptr);
// ...or scan an image already in RAM, with no file on disk:
// (apk/dex auto-detected)
engine->ScanBuffer(bytes, size, "app.apk", on_report, nullptr);
engine->Destroy();          // release the engine (never `delete` it)
```

`aavscan` is that snippet with argument parsing and printing around it:

```
aavscan [--debug] [--analysis] [--mt <threads>] <signature-db> <apk|dex file or dir>
```

## Scanning an APK

An APK is a zip, and every `classes*.dex` inside it is a scan target: multidex
splits one app across `classes.dex`, `classes2.dex` and so on, so stopping at
the first member misses whatever was moved out of it. `ApkScanner` unpacks each
one into memory and runs the DEX detection over it, merging the hits into one
verdict for the file.

Unpacking uses vendored miniz — one C file, no new dependency — and members are
scanned from RAM rather than written out, which is both faster and the only
option when the APK itself came from a buffer.

## Identifying a file

A scanner is chosen by what a file *is*, not by what it is called: `FileId`
reads the leading bytes off an `IStream` and reports DEX, ZIP, or unknown. An
extension is attacker-controlled and a renamed APK is the oldest trick there is.

Because it reads through `IStream`, the same identification runs on a path and
on a buffer.

## Scanning a DEX

`DexScanner` is the first thing that produces a verdict. It takes an `ITarget`,
runs `DexParser` over it, and returns a `ScanResult`: whether the file is
malicious, and the signature ids that say so. The two dimensions are merged as
a set union — either alone is a detection, and a signature found by both is
reported once.

`IScanner` is the shape every future format shares, so an APK or an ELF scanner
is a new implementation rather than a new caller.

## The signature database

Detection data ships as one file: a header, then one section per signature
dimension, the whole thing gzip-compressed inside Blowfish. `SigMgr` decrypts
and inflates it once at load and hands each section to the matcher that owns
that dimension, so nothing above it parses the container.

The encryption is obfuscation and tamper-evidence, not secrecy — the key is in
the engine. What it buys is that a database cannot be edited casually on a
device, and that a corrupted one fails at load rather than as a wrong verdict.

## One abstraction, files and memory

`ScanBuffer` is what the file/memory split was for: the same scanners, the same
identification and the same verdict, over bytes that were never written to
disk. A gateway holds an APK in RAM already, and copying it to a temporary file
to scan it is exactly the cost this avoids.


A scan target is either a file on disk or a block already in RAM, and the
engine should not care which. `IScanObject` splits into two shapes instead:

- `IStream` — sequential access with a cursor, for containers that are read
  front to back (an APK's zip directory).
- `ITarget` — the whole image addressable at once, for a leaf being parsed (a
  DEX, which seeks all over its own tables).

Each has a file and a memory implementation (`FileStream`/`MemStream`,
`FileTarget`/`MemTarget`), so one set of scanners serves both an on-disk scan
and a gateway scanning bytes it never wrote down.

## Ownership

Every engine object derives from `aav::IObject` and is released through
`Destroy()`, which runs `delete this` inside the library — so a caller never
links an `operator delete` for an engine type and a prebuilt library stays
usable across compiler and stdlib versions. Inside the engine that call is
never written by hand: `aav::ObjPtr<T>` is a `unique_ptr` whose deleter is
`Destroy()`, so ownership is RAII throughout.

`ObjPtr` is deliberately internal. `unique_ptr` is not ABI-stable across
compilers, which is exactly why the public surface hands out a raw pointer and
a `Destroy()` instead.

## Requirements

- CMake ≥ 3.21
- A C++17 compiler (GCC ≥ 9, Clang ≥ 10, or Apple Clang)
- *(optional)* Clang with the libFuzzer + sanitizer runtimes, to build the fuzzers
- zlib (`zlib1g-dev` on Debian/Ubuntu; preinstalled on macOS)

APK/zip support (miniz) is vendored under `third_party/` — no extra dependency.

Install everything (compilers, CMake, zlib, `clang-format`, `gcovr`, LLVM) in
one step: `scripts/install-deps-ubuntu.sh` (Debian/Ubuntu) or
`scripts/install-deps-macos.sh` (macOS); `--android` adds the SDK/NDK and a
JDK.

## Build

```bash
cmake --preset debug
cmake --build ../anti-android-virus-build/debug -j
```

or, the same thing in one line:

```bash
scripts/build.sh          # PRESET=release scripts/build.sh for -O2
scripts/test.sh           # build with tests enabled, then run them
scripts/run.sh            # generate a sample and scan it end to end
scripts/asan.sh           # ASan + UBSan build + tests
scripts/tsan.sh           # ThreadSanitizer build + tests
scripts/coverage.sh       # coverage build + gcovr report
scripts/format.sh         # clang-format check (--fix to apply)
scripts/tidy.sh           # clang-tidy check   (--fix to apply)
scripts/android.sh        # NDK cross-compile
scripts/android-app.sh    # assemble the demo app
scripts/clean.sh          # remove the build root
```

Nothing is written inside the checkout: the presets and the scripts both build
into the sibling `../anti-android-virus-build/`.

## Testing

Two suites, both under CTest: the doctest unit tests, and end-to-end tests that
run `sigtool` and `aavscan` as the user does and check that both sample
signatures fire.

The parsers are the untrusted-input surface, so the same suites also run under
AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
scripts/asan.sh
# or: cmake --preset asan && cmake --build --preset asan -j && ctest --preset asan
```

The scan thread pool needs a different runtime, and the two cannot share a
binary, so ThreadSanitizer is a separate build and a separate script:

```bash
scripts/tsan.sh
```

`scripts/coverage.sh` builds instrumented, runs the same suites and reports
line/branch coverage of `src/` through gcovr, failing under a floor
(`COVERAGE_FAIL_UNDER`, 65% by default). `--html` writes a browsable report.

Fuzzing the DEX parser (needs a Clang toolchain with libFuzzer):

```bash
FUZZ_TIME=60 scripts/fuzz.sh          # build and run
scripts/fuzz.sh --build-only          # just check the harness still compiles
```

A seedless run explores different input every time, so a fuzz run is a
developer's call rather than something to gate a change on; what is worth
keeping green is that the harness still compiles against the engine. Crashing
inputs are written under the fuzz build tree.

```bash
cmake --preset debug && cmake --build ../anti-android-virus-build/debug -j
ctest --preset debug
```

## Install / SDK

The engine ships as an SDK — public headers plus a static **and** a shared
library — installable to any prefix:

```bash
cmake --preset release && cmake --build ../anti-android-virus-build/release -j
cmake --install ../anti-android-virus-build/release --prefix /path/to/sdk
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

## Style and static analysis

Formatting is Google style with a few deliberate exceptions (`.clang-format`),
and the check is a script rather than a convention: `scripts/format.sh`
reports, `--fix` rewrites. It pins clang-format to one major, because layout
heuristics move between them and skew means one machine rejects what another
just produced.

`scripts/tidy.sh` runs clang-tidy over the same sources using the build's
compile database. `.clang-tidy` records which check families are off and why —
each disabled family carries its reason, so the list is a set of decisions
rather than a set of things nobody got to. `third_party/` is excluded from
both: vendored code is not ours to reformat or lint.

## Continuous integration

`build.yml` runs the unit and end-to-end suites on Ubuntu and macOS, crossing
each platform's compilers with Debug and Release. Release is an axis rather
than an afterthought: `-O2` takes different paths through the DEX and zip
parsers than `-O0`, and `assert()` is compiled out, so a Debug-only suite never
executes the code that ships.

Every step is a preset, so a red job reproduces locally with the one command it
ran — `ctest --preset release` — rather than by transcribing flags out of a
workflow file.

## Project layout

```
.
├── CMakeLists.txt   # root: language settings, warnings; delegates to subdirs
├── CMakePresets.json# debug / release
├── include/aav/     # public SDK headers
├── android/         # Gradle + NDK app; JNI bridge over the engine
├── apps/
│   ├── aavscan/     # CLI scanner (thin facade consumer)
│   └── sigtool/     # sample DEX + signature-DB generator
├── src/
│   ├── api/aav/     # internal object API (interfaces, factories) — not exported
│   ├── engine/      # the IEngine facade implementation
│   ├── platform/    # file/memory primitives (FileStream, FileTarget, MemTarget)
│   ├── sig/         # signature-DB load/decrypt/decompress, format
│   ├── dex/         # DEX parser + path/opcode/operand/logic matchers
│   ├── scan/        # file-type id (FileId) + APK (zip) unpacking
│   └── utils/       # crc32, leb128, blowfish, gzip inflate, logger
├── tests/
│   ├── unit/        # doctest white-box unit tests (one binary)
│   └── e2e/         # generate-and-scan end-to-end CTest drivers
├── fuzz/            # libFuzzer harness for the DEX parser
├── third_party/     # vendored: miniz (zip), doctest
├── scripts/         # build.sh, test.sh, run.sh, clean.sh
└── docs/            # Thesis.md, Signatures.md, SignatureDbFormat.md
```

## Why CRC32 and LEB128 first

They are the two things the rest of the design assumes. Detection reduces every
method to CRC32s of its opcode and operand sequences, so the checksum is on the
hot path of every scan rather than a utility; and DEX stores nearly every count,
offset and index as an unsigned or signed LEB128, so the parser cannot read a
single class before it can decode one.

The logger is here for the same reason both of those are: it has to be usable
from the first layer up, and on Android it has to reach logcat rather than
stderr.

## Android

The engine (`libaav`) and the `aavscan` CLI **cross-compile for Android** via
the NDK — the same sources, no Android-specific branch except the logger, which
routes to logcat there instead of stderr:

```bash
ABI=arm64-v8a scripts/android.sh
# or, by hand:
cmake -S . -B ../anti-android-virus-build/android \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 \
  -DAAV_BUILD_CLI=OFF -DAAV_BUILD_TOOLS=OFF -DAAV_BUILD_TESTS=OFF
cmake --build ../anti-android-virus-build/android -j
```

On-device is the case the whole design was aimed at: no emulation, no server
round-trip, and a scan that costs a parse.

A demo app (`com.av.aav`) under [`android/`](android/README.md) drives the
engine on the device through JNI. Its bridge is a consumer of the public
`IEngine` facade and statically links `libaav`, so there is no separate engine
`.so` and no engine internals in the app:

```bash
cd android && ./gradlew :app:assembleDebug     # SDK 36 / NDK 29 / JDK 17
```

## License

Licensed under the MIT License — see [`LICENSE`](LICENSE).
