\mainpage aav API reference

This is the generated reference for `aav`'s interface headers — a static
(non-emulating) Android malware detection engine that parses DEX bytecode and
matches it against a multi-dimensional signature database. It documents what
each interface is for and how the pieces fit together. The narrative
documentation is not here: it lives in the repository, and
[docs/README.md](https://github.com/yanghuafang/anti-android-virus/blob/main/docs/README.md)
indexes it.

This page exists only as the landing page for the generated site; it is not one
of the guides.

## Two surfaces, and which one you want

The distinction this site is most useful for is one the source tree encodes in
its directory layout and nothing else makes visible:

| Surface | Header directory | Who uses it |
| --- | --- | --- |
| **Public SDK** | `include/aav/` | anything linking `libaav` — the CLI, the JNI bridge, your application |
| **Internal object API** | `src/api/aav/` | the engine's own components; never installed |

If you are embedding the engine, aav::IEngine is the entire API — plus
aav::IObject for the `Destroy()` contract. Everything else on this site is
engine internals, documented because the layering is worth reading, not because
you have to call it.

The split is deliberate and it is an ABI decision. Only PODs, C strings and a
function pointer cross the public boundary, so a prebuilt `libaav.so` keeps
working across compiler and stdlib versions; aav::ObjPtr, the RAII owner the
engine uses everywhere internally, is a `std::unique_ptr` alias and therefore
stays on the inside.

## What this site adds

The prose here is the same prose as in the headers, so reading the sources
directly loses nothing. What is easier to see rendered is the hierarchy that
the engine's central design claim rests on: aav::IScanObject splits into
aav::IStream (sequential, for archives) and aav::ITarget (whole-content buffer,
for leaf images like DEX), and each of those has a file implementation and a
memory implementation. That is what lets the *same* scanner run against a file
on disk and a block in RAM — `Scan()` and `ScanBuffer()` — and in the source it
is nine headers and a `: public` clause at a time.

For the scan pipeline stage by stage, see
[docs/Architecture.md](https://github.com/yanghuafang/anti-android-virus/blob/main/docs/Architecture.md);
for the interface hierarchy as prose, see
[docs/ObjectModel.md](https://github.com/yanghuafang/anti-android-virus/blob/main/docs/ObjectModel.md).
