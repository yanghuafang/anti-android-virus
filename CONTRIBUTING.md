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

`aav` targets **Ubuntu 24.04 / 26.04 (x86_64)**, **macOS (ARM64)**, and
**Android (arm64-v8a)**. You need CMake ≥ 3.20, a C++17 compiler (GCC ≥ 9,
Clang ≥ 10, or Apple Clang), and zlib. APK/zip support (miniz) and the unit-test
framework (doctest) are vendored. Install the full toolchain in one step with
`scripts/install-deps-ubuntu.sh` (Debian/Ubuntu) or `scripts/install-deps-macos.sh`
(macOS). See [docs/Building.md](docs/Building.md).

## Build

```bash
scripts/build.sh          # configure + build the engine, aavscan, sigtool
```

or manually:

```bash
cmake --preset debug -DAAV_BUILD_TESTS=ON && cmake --build build/debug -j
```

## Test

Every change must keep the suite green:

```bash
scripts/test.sh           # build + unit (doctest) + end-to-end (CTest)
scripts/asan.sh           # AddressSanitizer + UBSan build + tests
```

or directly:

```bash
ctest --test-dir build/debug --output-on-failure
```

The DEX parser is the untrusted-input attack surface — if you touch it, also run
the fuzzer (Clang):

```bash
cmake --preset fuzz -DCMAKE_CXX_COMPILER=clang++
cmake --build build/fuzz --target fuzz_dexfile -j
./build/fuzz/bin/fuzz_dexfile -max_total_time=60
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

- **C++17**, formatted with `clang-format` using the repo's
  [`.clang-format`](.clang-format) (Google base, 2-space indent, 80 columns).
  Run `scripts/format.sh --fix` on the files you touch.
- Everything engine-side lives under `namespace aav`; file-local helpers go in an
  anonymous namespace. See [docs/ObjectModel.md](docs/ObjectModel.md).
- Own heap objects with RAII (`std::unique_ptr` / `aav::ObjPtr`), not manual
  `new` / `delete`.
- Comments explain **intent and trade-offs**, not restate the code.
- Keep the public SDK surface (`include/aav/`) ABI-clean — only PODs, C strings
  and callbacks; no `std::` containers or smart pointers cross it.

## Commit & pull request

- Write commit messages in the **imperative mood**, capitalized, ending with a
  period — e.g. `Add invoke-custom opcode lengths (DEX 038/039).`
- Keep unrelated changes out of the same commit; one idea per pull request.
- Before opening a PR: run `scripts/format.sh`, `scripts/test.sh`, and
  `scripts/asan.sh` locally, and update any affected docs.
- Describe **what** changed and **why**; confirm CI is green (Ubuntu 24.04 /
  26.04, macOS, Android).

## Scope

`aav` is intentionally a compact detection engine, and the bundled signature DB
is a **synthetic sample**, not a real malware feed. Large additions (new file
formats, dynamic/emulated analysis, a real signature feed) are out of scope for
the core — please open an issue to discuss before starting large work.

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
