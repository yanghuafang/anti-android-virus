# Object model & interface hierarchy

`aav` is built on a small set of pure-virtual interfaces (COM-influenced, but
modernized). The payoff is a clean separation that lets the **same** scanning
code run against a file on disk *or* a block of memory, and lets the engine ship
as an ABI-stable SDK. Everything lives under a single `namespace aav`.

## The hierarchy

```
IObject                    // Destroy() -- ABI-safe release
├── IScanObject            // GetSize / GetName / GetFullPath / GetProperty
│   ├── IStream            // Read / Write / Seek / Tell / GetView  (traverse an archive)
│   │   ├── IFileStream    //   backed by a file on disk   Init(FileSource*)
│   │   └── IMemStream     //   backed by a RAM buffer      Init(MemSource*)
│   └── ITarget            // GetBuf  (a leaf object with one contiguous buffer)
│       ├── IFileTarget    //   backed by a file on disk   Init(FileSource*)
│       └── IMemTarget     //   backed by a RAM buffer      Init(MemSource*)
├── IScanner               // Init / ScanStream / ScanTarget   (ApkScanner, DexScanner)
├── ISigMgr                // load/decrypt the signature DB, name lookup   (SigMgr)
├── IFileID                // classify DEX / ZIP / unknown from magic       (FileID)
├── IFileMap / IFileSystem // platform I/O primitives (mmap, remove, ...)
└── IModule                // dlopen-style dynamic library loader
```

## Two axes: Stream vs Target, File vs Memory

A scan object is factored along **two independent axes**:

- **`IStream` vs `ITarget` — *how* the bytes are consumed.**
  - An **`IStream`** is something you *traverse*: seekable and readable, and (for
    an archive such as an APK/zip) something you extract entries from. The APK
    scanner takes an `IStream`.
  - An **`ITarget`** is a *leaf* scan object exposing one contiguous buffer via
    `GetBuf()` — what the DEX parser consumes directly. The DEX scanner takes an
    `ITarget`.
- **File vs Memory — *where* the bytes live.**
  - `IFileStream` / `IFileTarget` are backed by a file on disk.
  - `IMemStream` / `IMemTarget` are backed by a caller-owned RAM buffer.

Because the scanners program to `IStream` / `ITarget` (not to files), the exact
same `DexScanner` and `ApkScanner` run on **both** on-disk files and in-memory
images. That is what lets `IEngine::Scan(path, ...)` (files/dirs) and
`IEngine::ScanBuffer(data, size, ...)` (RAM — e.g. a gateway scanning an APK it
never writes to disk) share one implementation.

## Zero-copy: `IStream::GetView`

`IStream::GetView(&ptr, &size)` hands back a read-only pointer to the whole
content with no copy when the stream is contiguous — a `MemStream` returns its
own buffer; a `FileStream` memory-maps the file (`IFileMap`). The APK scanner
uses it to unpack `classes.dex` straight from the mapped/in-memory image; if a
stream cannot provide a view it transparently falls back to `Seek` / `Read`.

## Ownership & lifetime (RAII)

- Objects are created by factories (`aav::MakeDexScanner()`,
  `aav::MakeFilestream()`, …) that return an owning **`aav::ObjPtr<T>`** — a
  `std::unique_ptr` whose deleter calls `IObject::Destroy()`. There is no manual
  reference counting and no `retain` / `release`.
- `IObject::Destroy()` is defined out-of-line inside the library, so a caller
  never links `operator delete` for engine objects — this is what keeps
  destruction **ABI-safe** across compilers / stdlib versions. Callers never
  `delete` an `IObject` (its destructor is protected).

## Public vs internal

- **Public SDK** (`include/aav/`): only the facade — `aav::IEngine`,
  `aav::IObject`, and the POD `EngineConfig` / `ScanReport`. ABI-clean: no `std::`
  types cross it. See [Architecture.md](Architecture.md) and the README's
  *Embedding* section.
- **Internal** (`src/api/aav/`): the interfaces above, the factories
  (`factory.h`), and `aav::ObjPtr` — used by first-party code (the engine, the
  JNI bridge) but **not** installed.

Public and internal alike live under one `namespace aav`; translation-unit-local
helpers use an anonymous namespace nested inside it.
