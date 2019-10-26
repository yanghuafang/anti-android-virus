# anti-android-virus (aav) — Android malware static detection engine

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

> **Status:** early. The layers are landing bottom-up; there is no engine
> facade and no command-line scanner yet.

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

## The signature database

Detection data ships as one file: a header, then one section per signature
dimension, the whole thing gzip-compressed inside Blowfish. `SigMgr` decrypts
and inflates it once at load and hands each section to the matcher that owns
that dimension, so nothing above it parses the container.

The encryption is obfuscation and tamper-evidence, not secrecy — the key is in
the engine. What it buys is that a database cannot be edited casually on a
device, and that a corrupted one fails at load rather than as a wrong verdict.

## One abstraction, files and memory

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
- zlib (`zlib1g-dev` on Debian/Ubuntu; preinstalled on macOS)

## Build

```bash
cmake --preset debug
cmake --build ../anti-android-virus-build/debug -j
```

or, the same thing in one line:

```bash
scripts/build.sh          # PRESET=release scripts/build.sh for -O2
scripts/test.sh           # build with tests enabled, then run them
scripts/clean.sh          # remove the build root
```

Nothing is written inside the checkout: the presets and the scripts both build
into the sibling `../anti-android-virus-build/`.

## Testing

Tests are built by the `debug` and `release` presets and run under CTest:

```bash
cmake --preset debug && cmake --build ../anti-android-virus-build/debug -j
ctest --preset debug
```

## Project layout

```
.
├── CMakeLists.txt   # root: language settings, warnings; delegates to subdirs
├── CMakePresets.json# debug / release
├── include/aav/     # public SDK headers
├── src/
│   ├── api/aav/     # internal object API (interfaces, factories) — not exported
│   ├── engine/      # the object base shared by every engine object
│   ├── platform/    # file/memory primitives (FileStream, FileTarget, MemTarget)
│   ├── sig/         # signature-DB load/decrypt/decompress, format
│   ├── dex/         # DEX parser: classes, methods, code items
│   └── utils/       # crc32, leb128, blowfish, gzip inflate, logger
├── tests/
│   └── unit/        # doctest white-box unit tests (one binary)
├── third_party/     # vendored: doctest
├── scripts/         # build.sh, test.sh, clean.sh
└── docs/
    └── Thesis.md    # the method this engine implements
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

## License

Licensed under the MIT License — see [`LICENSE`](LICENSE).
