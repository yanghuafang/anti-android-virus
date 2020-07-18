# Contributing to `aav`

Thanks for your interest in `aav` (anti-android-virus), a static Android malware
detection engine. Contributions of all sizes are welcome: bug fixes, new tests,
clearer docs, DEX-parser hardening, and engine features.

Because `aav` is primarily a **research / educational** project, clarity and
small, reviewable changes matter more than large features.

## Ways to contribute

- **Fix a bug** in the DEX parser, the scanners, the signature manager, or the
  platform layer.
- **Harden the parser** — it consumes untrusted input, so fuzz-found crashes and
  bounds fixes are especially valuable.
- **Add a test** — a doctest unit test or an end-to-end CTest case (see below).
- **Improve documentation** in `docs/`, or add comments that explain *why*.
- **Extend the engine** — new DEX opcode/version support, matchers, or platforms.

## Prerequisites

`aav` targets **Linux (x86_64)**, **macOS (ARM64)**, and **Android
(arm64-v8a)**. You need CMake ≥ 3.21, a C++17 compiler (GCC ≥ 9, Clang ≥ 10, or
Apple Clang), and zlib; the checks additionally want clang-format, clang-tidy,
gcovr, doxygen and graphviz. APK/zip support (miniz) and the unit-test
framework (doctest) are vendored. Install the full toolchain in one step with
`scripts/install-deps-ubuntu.sh` (Debian/Ubuntu) or
`scripts/install-deps-macos.sh` (macOS). See
[docs/Building.md](docs/Building.md).

## Build

```bash
scripts/build.sh          # configure + build the engine, aavscan, sigtool
```

or manually:

```bash
cmake --preset debug && cmake --build --preset debug -j
```

## Test

Every change must keep the suite green:

```bash
scripts/test.sh           # build + unit (doctest) + end-to-end (CTest)
PRESET=release scripts/test.sh   # the same suite with -O2 and no asserts
scripts/asan.sh           # AddressSanitizer + UBSan build + tests
scripts/tsan.sh           # ThreadSanitizer over the scan thread pool
```

or directly — CI runs these exact preset names, so a red job reproduces here:

```bash
ctest --preset debug
```

The DEX parser is the untrusted-input attack surface — if you touch it, also run
the fuzzer (Clang):

```bash
cmake --preset fuzz -DCMAKE_CXX_COMPILER=clang++
cmake --build ../anti-android-virus-build/fuzz --target fuzz_dexfile -j
../anti-android-virus-build/fuzz/bin/fuzz_dexfile -max_total_time=60
```

## Adding a test

- **Unit test (white-box):** add a `TEST_CASE` to a file under
  [`tests/unit/`](tests/unit/) (doctest); new files go in the
  `aav_unit_tests` list in [`tests/CMakeLists.txt`](tests/CMakeLists.txt).
- **End-to-end:** the [`tests/e2e/scan_*.cmake`](tests/e2e/) drivers generate a
  sample with `sigtool` and scan it with `aavscan` / the mem-scan checker,
  asserting the expected signatures fire.

Use [`tests/unit/test_dexparse.cc`](tests/unit/test_dexparse.cc) as a template.
When hardening the parser, prefer a test that feeds malformed input and asserts
"no crash / no out-of-bounds read" under the ASan build.

## Coding style

- **C++17**, written to the
  [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html)
  and formatted with `clang-format` using the repo's
  [`.clang-format`](.clang-format) (Google base, 2-space indent, 80 columns).
  `.clang-tidy` runs the whole `google-*` check family and CI keeps it clean,
  so most of the guide is enforced rather than remembered. Four rules it states
  that no check implements, and that review has to carry:

  - **Include a project header by its path from an include root** —
    `#include "utils/log.h"`, never `"log.h"`. The internal roots are `src/`
    and `src/api/` only, so each spelling names exactly one file and the layer
    a file reaches into is visible at the use site.
  - **Acronyms are words** — `FileId`, `DexCodeCrc`, `AcTree`,
    `GetMalwareSigIds`; not `FileID` or `DexCodeCRC`. (The `I` on `IStream` is
    a prefix, not an acronym.)
  - **State copy and move** — never leave them implicit. Everything under
    `IObject` inherits the deletion from the root; a class outside that
    hierarchy declares its own, with the reason it cannot be copied.
  - **Mark a concrete implementation `final`** — every one is a leaf reachable
    only through its factory, and `final` is also what makes the
    `Init()`/`Uninit()` call in its destructor a non-virtual call.
- Three scripts enforce the style, each is its own CI job, and each fails the
  build — run them before committing:

  ```bash
  scripts/format.sh --fix   # clang-format
  scripts/tidy.sh --fix     # clang-tidy; --fix applies what it can
  scripts/docs.sh           # Doxygen API reference; --open shows it
  ```

  Both print the binary and version they used, since layout and check
  diagnostics move between clang majors. On macOS they take the tools from
  Homebrew's keg-only `llvm` (Xcode ships neither). Neither touches
  `third_party/` — reformatting vendored miniz and doctest would make every
  upstream resync unreadable.
- The clang-tidy check list in [`.clang-tidy`](.clang-tidy) is curated, not the
  full upstream set, and every disabled family carries the reason it is off. If
  a check would help, re-argue it there rather than silencing findings with
  `NOLINT`. Note what that file is *not* for: bug-hunting is left to the
  ASan/UBSan build and the fuzzer, which execute the code instead of guessing
  about it.
- Everything engine-side lives under `namespace aav`; file-local helpers go in an
  anonymous namespace. See [docs/ObjectModel.md](docs/ObjectModel.md).
- Own heap objects with RAII (`std::unique_ptr` / `aav::ObjPtr`), not manual
  `new` / `delete`.
- Comments explain **intent and trade-offs**, not restate the code. Reserve them
  for architecture, algorithms, non-obvious logic, and how to use an interface;
  do not narrate line by line.
- Interface headers (`include/aav/`, `src/api/aav/`) use `///` doc comments, so
  the prose there is also the [API reference](https://yanghuafang.github.io/anti-android-virus/).
  A `///` block's first sentence is its brief; a trailing `///<` documents the
  member it follows.
- Keep the public SDK surface (`include/aav/`) ABI-clean — only PODs, C strings
  and callbacks; no `std::` containers or smart pointers cross it.

## Commit & pull request

- Write commit messages as **Conventional Commits** — `type(scope): description`,
  lowercase, imperative, no trailing period, e.g.
  `fix(dex): bound the code-item walk to the map section`. The types in use are
  `feat`, `fix`, `refactor`, `perf`, `docs`, `test`, `build` and `ci`; the scope
  is the subtree the change lands in (`dex`, `sig`, `scan`, `platform`,
  `engine`, `scripts`, `android`, …).
- Put the *why* in the body as bullets wrapped at 72 columns — what the change
  does is already visible in the diff; what it rules out, and why the obvious
  alternative was not taken, is not.
- Keep unrelated changes out of the same commit; one idea per pull request.
- Before opening a PR: run `scripts/format.sh`, `scripts/tidy.sh`,
  `scripts/docs.sh`, `scripts/test.sh`, `scripts/asan.sh` and `scripts/tsan.sh`
  locally, and update any affected docs.
- Describe **what** changed and **why**; confirm CI is green (Linux, macOS,
  Android).

## Scope

`aav` is intentionally a compact detection engine, and the bundled signature DB
is a **synthetic sample**, not a real malware feed. Large additions (new file
formats, dynamic/emulated analysis, a real signature feed) are out of scope for
the core — please open an issue to discuss before starting large work.

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
