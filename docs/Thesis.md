# An Efficient Android Malware Static Detection System

*Yanghua Fang (方阳华) · Beijing University of Posts and Telecommunications*

*Updated English edition. The detection method follows the original master's
thesis; the architecture and implementation describe the current open-source
engine in this repository. Full citation: [Provenance](#provenance).*

## Contents

- [Abstract](#abstract)
- [1. Introduction](#1-introduction)
- [2. Background and Related Work](#2-background-and-related-work)
- [3. Detection Method](#3-detection-method)
- [4. System Design and Implementation](#4-system-design-and-implementation)
- [5. Evaluation](#5-evaluation)
- [6. Conclusion and Future Work](#6-conclusion-and-future-work)
- [References](#references)
- [Provenance](#provenance)

---

## Abstract

Android runs on the large majority of the world's smartphones, and the openness
of its ecosystem — fragmented app stores with weak review, and devices that
rarely receive timely patches — has made it a persistent malware target.
Detecting Android malware is therefore of real social and economic importance,
and static (non-emulating) analysis is the fastest, most portable, and most
predictable way to do it, both on-device and in server-side triage.

This thesis presents an efficient static detection method that models malicious
behavior as a **boolean combination of multi-dimensional code-behavior
fragments**, complemented by **multi-pattern matching over package paths**. A
class or method is characterized by features drawn from its **opcode sequence**
and its **string (constant-operand) sequence**, each reduced to a CRC-32 and
combined with **AND / OR / XOR / NOT** logic. This representation captures the
essence of a behavior precisely yet flexibly, generalizing across the variants
of a malware family where single-feature matching does not. A package-path
Aho-Corasick variant and a fast-opcode **bitmap pre-filter** that skips methods
which cannot match together reduce whole-file scanning to roughly
**O(n·log S)** for *n* methods and *S* signatures — well below the O(n·S) of
linear matchers.

The method is realized as a portable **C++17** engine with an ABI-stable SDK, a
command-line scanner, and an Android application, running identically on Linux,
macOS, and Android. Its DEX parser is written from scratch and hardened against
the malformed inputs malware uses to defeat off-the-shelf tools, and a uniform
scan-object abstraction lets the same scanners operate on a file on disk or a
buffer in memory. In a head-to-head comparison with two shipping commercial
products, the approach achieves higher detection, a false-positive rate of zero,
and 2–5× faster scanning.

**Keywords:** Android, malware, static detection, behavior fragments, logic
combination, Aho-Corasick, C++.

---

## 1. Introduction

### 1.1 Motivation

Smartphones concentrate a person's most sensitive information — contacts,
messages, photos, location, and social and payment accounts. Android's open,
low-barrier ecosystem has produced hundreds of fragmented app markets whose
review is easily evaded, while OS and hardware fragmentation mean security
patches reach only a fraction of devices in time. Malware is correspondingly
abundant, and it increasingly bundles multiple payloads and applies
anti-analysis techniques.

Among detection strategies, **static scanning** inspects an application without
running it. It is safe (the sample never executes), portable (the same logic
serves device and cloud), and — with the right algorithms — fast and precise
enough for real-time use. Dynamic sandboxing finds novel behavior but is hard to
trigger, easy to evade, and resource-heavy; statistical/ML classifiers are
powerful for triage but too large and false-positive-prone for shipping
verdicts. This thesis focuses on making *static* detection accurate, robust to
obfuscation, and fast.

### 1.2 Problem and threat model

The adversary controls the sample. In particular, malware may:

- **obfuscate package names** (`com.a.b.c`, or a plausible impostor name), so
  path-only features misfire and break across versions;
- **obfuscate method content** by shuffling registers, defeating byte-for-byte
  code matching while preserving behavior;
- **repackage several payloads** into one app, so a scan must examine the *whole*
  file rather than stop at the first hit;
- **craft malformed DEX** (e.g. data structures placed mid-method) that runs on
  the device but crashes common parsers.

A detector must therefore be **whole-file**, **resilient to obfuscation**,
**memory-safe on untrusted input**, and **fast**, on both mobile and server.

### 1.3 Approach and contributions

This thesis makes the following contributions:

1. A **detection method** that combines package-path multi-pattern matching with
   the boolean combination of multi-dimensional per-method behavior fragments,
   giving accurate, broad-spectrum coverage while keeping scan cost low
   (Chapter 3).
2. A **negation-based whitelist** that can suppress a specific false positive —
   even a single ad inside a single app — without disabling a signature globally
   (§3.5).
3. A portable, **memory-safe implementation**: a from-scratch DEX parser that
   resists anti-analysis inputs, a compact encrypted signature database, a
   uniform file/memory scan abstraction, an ABI-stable SDK, and parallel
   scanning (Chapter 4).
4. An **evaluation** against two representative commercial detectors on detection
   rate, false-positive rate, and scan speed (Chapter 5).

### 1.4 Outline

Chapter 2 surveys the necessary background and the shortcomings of existing
detectors. Chapter 3 presents the detection method. Chapter 4 describes the
system's architecture and implementation. Chapter 5 evaluates it, and Chapter 6
concludes.

---

## 2. Background and Related Work

### 2.1 Android applications and DEX

An Android application ships as an **APK** — a ZIP archive whose executable core
is `classes.dex` (with optional `classes2.dex`, … for *multidex*), alongside
resources, a manifest, and native `lib/*.so` libraries. `classes.dex` holds
**Dalvik bytecode**, run by the Dalvik VM on older systems and compiled
ahead-of-time to ART/OAT on Android 5.0+. Both use the same DEX format and
instruction set, and the original DEX bytes are always recoverable (they are
embedded inside ODEX/OAT). Analyzing the DEX is therefore **sufficient and
version-stable**, whereas chasing per-device AOT artifacts is brittle — so this
work scans DEX bytecode.

A DEX file has a fixed **header**, **index tables** (strings, types, prototypes,
fields, methods, class definitions), and a **data** region. Enumerating
`class_defs` and each class's methods walks the application's behavior; this is
the basis of scanning.

### 2.2 Evasion techniques

Malware authors routinely apply the techniques listed in §1.2 — package-name and
content obfuscation, multi-payload repackaging, and parser-breaking malformed
DEX — and, beyond the scope of this work, DEX packing and native-library
packing. The design in Chapter 3 is built specifically to withstand the first
four, and the from-scratch parser (§4.6) neutralizes tool-exploiting inputs.

### 2.3 Limitations of existing detectors

Surveying shipping detectors reveals recurring weaknesses that motivate this
design:

- **Path-only matching** is fast but blind to obfuscated or impostor package
  names.
- **Byte-equality bytecode matching** is defeated by register-shuffle content
  obfuscation, ties one signature to one variant (no family coverage), scans in
  **O(n·S)**, and misfires on features extracted from tiny methods.
- **Whole-file whitelisting** is impractical for repackaged APKs, which can carry
  several payloads and be re-signed arbitrarily.
- **Building on the platform's `libdex`** is slow and inflexible (no STL, hard to
  debug off-device), and many tools exceed memory limits on very large apps.

---

## 3. Detection Method

### 3.1 Overview

Detection combines two complementary matchers over a whole DEX file: a
**package-path** matcher that catches malware whose paths are not heavily
obfuscated, and a **code-behavior** matcher that identifies malware from its
bytecode even under path obfuscation or impostor naming. Both feed a heuristic
**boolean combination** that yields the final verdict.

### 3.2 Package-path multi-pattern matching

Every class or method has a dotted path such as `com.adhoc.MainActivity`. Four
match relations are useful: a feature string may **equal** the path, or be its
**prefix**, **suffix**, or an interior **substring**. Matching each feature
linearly (e.g. with KMP) costs O(S) in the number of signatures and stores whole
strings.

Instead, the method uses an **Aho-Corasick variant** whose **nodes are the CRC-32
of lower-cased path segments** rather than characters. A path is split on `.`
into segments; segment *i* occupies **layer *i*** of the trie. Sibling nodes at a
layer are kept **sorted by CRC-32** so a segment is located by **binary search**,
and only **leaf nodes are terminal** (no signature may be a prefix of another).
Matching walks the trie segment by segment, following **failure links** on a miss
to avoid backtracking. The four match relations fall out of comparing the path's
current and maximum layers with the feature's, so no separate string comparison
is needed. Per lookup this is **O(log S)**, and the CRC-32 representation shrinks
storage dramatically versus storing paths.

### 3.3 Multi-dimensional code-behavior fragments

A Dalvik instruction consists of an opcode and operands (register IDs and
string/type/member/method indices). Register IDs, and class/member/method names,
are obfuscatable and cannot be trusted as features. From the trustworthy parts,
each method yields **behavior fragments**, each reduced to a **CRC-32**:

1. **Address-independent opcode sequence** — the opcodes in order, with
   branch-offset operands zeroed so relative jumps do not perturb the feature.
   Switch and fill-array-data *payloads* (which may appear mid-method to trip up
   parsers) are explicitly not mis-parsed as instructions.
2. **String sequence** — the referenced constant strings, lower-cased, in order
   of appearance.

Because opcodes survive register shuffling and constant strings survive path
obfuscation, these fragments are stable against common obfuscation. The
combination framework in §3.4 is dimension-agnostic: additional fragment types —
for example a system-API-call sequence, whose names cannot be obfuscated without
breaking the call — slot in without changing the matcher.

### 3.4 Boolean combination of fragments

Each malware signature (`sig_id`) maps to a **logic block** of four arrays —
**AND, OR, XOR, NOT** — each holding zero or more fragment references (fragment
type + CRC-32 + the ID of the method it came from; equal method IDs mean "the
same method"). Fragments within an array are CRC-sorted for binary search. A
signature is judged **present** by:

- **AND** — present iff *all* listed fragments are present;
- **OR** — present iff *at least one* is present;
- **XOR** — *not* present if *two or more* are present (a veto);
- **NOT** — *not* present if *one or more* are present (a veto).

Combining several small, individually-ambiguous fragments into one expression
captures a variant's essence precisely and generalizes across a family, avoiding
the false positives of single-feature matching.

### 3.5 Negation-based precise whitelist

Whole-file whitelisting is unsuitable for Android, where a repackaged app can
contain several payloads. The **XOR** and **NOT** (negation) arrays provide a
*precise* whitelist instead: negation outranks affirmation, so a `NOT` fragment
can veto one specific false positive, and an `XOR` pairing (a benign method's
feature together with an ad's feature) can suppress exactly *one ad in one app*
while leaving the signature active everywhere else.

### 3.6 Bitmap method pre-filter

Most methods match no signature, so scanning each one in full is wasteful. For
every method that ever contributed a feature, the first few opcodes (the low byte
of each two-byte opcode) are packed **pairwise into 16-bit keys**, and each key's
bit is set in a per-position **bitmap**. At scan time the current method's keys
are looked up in these bitmaps in **O(1)**; the method is scanned in full only if
*all* keys hit, and skipped otherwise. Pairwise keys keep the bitmaps small and
cache-resident. (Sizing details for this implementation are in §4.6.)

### 3.7 Complexity

For a file of *n* methods and a database of *S* signatures, path matching costs
O(log S) per class, the bitmap pre-filter costs O(1) per method, and each
retained method performs O(log S) sorted-table lookups. Whole-file scanning is
thus about **O(n·log S)**, compared with **O(n·S)** for linear signature
matchers — the source of the measured speed advantage in Chapter 5.

---

## 4. System Design and Implementation

### 4.1 Architecture

The system is a portable **C++17 engine library**, packaged as an SDK, with thin
consumers layered on top:

```
 Consumers   aavscan (CLI)   Android app (Java) ── JNI ──┐   sigtool (fixtures)
 ─────────────────────────────────────────────────────────┼─────────────────────
 Public SDK  <aav/…>:  IEngine (Init / Scan / ScanBuffer) + POD ScanReport callback
 ─────────────────────────────────────────────────────────┴─────────────────────
 Engine      Engine · FileID · ApkScanner · DexScanner · SigMgr
 (namespace  DexParser · DexFile · DexCode · ACTree · Dex{Path,Code}SigMgr
  aav)       Dex{Path,Code}ScanResult(+Mgr)
 ─────────────────────────────────────────────────────────────────────────────
 Platform    IScanObject → IStream {FileStream, MemStream} / ITarget {FileTarget,
             MemTarget} · FileMap (mmap) · Module (dlopen)
 Utilities   Crc32 · Blowfish · gzip (zlib) · uleb128 · logging · miniz (zip)
```

The native engine depends on neither Java nor the Dalvik/ART runtime, so the same
code runs on Android and on Linux/macOS servers with identical results — enabling
both on-device scanning and cloud-side triage. The engine lives entirely in the
`aav` namespace.

### 4.2 A uniform scan-object abstraction (files and memory)

Scanners treat an on-disk file and an in-RAM buffer through one interface family,
so a scan target may equally be a file, a memory block, or a network stream:

- **`IScanObject`** — the common base: `GetSize`, `GetName`, `GetFullPath`,
  `GetProperty`.
- **`IStream`** — a seekable byte stream (`Read`/`Seek`/`Tell`), for **archives**
  consumed sequentially. Concrete types: **`FileStream`** (buffered I/O plus a
  lazily memory-mapped view) and **`MemStream`** (a caller buffer).
- **`ITarget`** — a scan *leaf* exposing its whole content as one contiguous
  buffer (`GetBuf`), used by the DEX parser for random access. Concrete types:
  **`FileTarget`** (memory-mapped via `FileMap`) and **`MemTarget`** (a caller
  buffer).

`IStream::GetView` hands back a **zero-copy** pointer to the entire content when
the backing is contiguous (a mapped file or a buffer), so the APK scanner works
without copying, falling back to `Seek`/`Read` otherwise. Memory-mapping files
and streaming oversized inputs keeps memory use low regardless of app size, and
lets the *same* scanners run on files (`Scan`) or on RAM (`ScanBuffer`).

### 4.3 Object model and SDK

Objects use **RAII** throughout. The base `IObject` exposes a single virtual
**`Destroy()`**, defined inside the library so ownership is ABI-safe across
compilers and standard-library versions; its destructor is protected, so callers
never `delete` directly. A `unique_ptr`-like **`ObjPtr<T>`** owns objects via
`Destroy()`, and internal objects are constructed by **`MakeX()`** factories.

The **public SDK** exposes only an **`IEngine`** facade and plain data. It is
**ABI-stable** — only PODs, C strings, integers, and one function pointer cross
the boundary, never `std::` types — so a consumer built with a different
toolchain links safely:

```cpp
IEngine* eng = MakeEngine();                            // nullptr on failure
eng->Init(sig_db_path, &EngineConfig{ /* threads, flags */ });
eng->Scan(path, cb, user_data);                         // file or directory
eng->ScanBuffer(data, size, name, cb, user_data);       // in-memory APK or DEX
eng->Destroy();
```

Each scanned file is reported through `ScanCallback(const ScanReport*, void*)`.
The POD `ScanReport` carries the path, `is_malware` / `is_white`, the matched
`sig_ids[]` with resolved `names[]`, and — under analysis mode — a per-class
feature tree. All pointers are engine-owned and valid only for the callback's
duration.

### 4.4 Scan pipeline

`Scan` classifies the path and dispatches:

1. **Identification** — `FileID` reads magic bytes: DEX (`dex\n0XY\0`, versions
   035–040) or ZIP/APK (`PK\x03\x04`).
2. **APK** — `ApkScanner` opens the zip (vendored **miniz**), extracts each
   **multidex** member (`classes.dex`, `classes2.dex`, …), scans each as a DEX,
   and merges the results.
3. **DEX** — `DexScanner` runs `DexParser` over the image via an `ITarget`.
4. **Report** — malware `sig_id`s are resolved to names and delivered through the
   callback.

`DexParser::Scan` walks each class: it applies path matching first (a hit
classifies the class), then walks the methods, applies the bitmap pre-filter,
extracts the opcode- and string-sequence fragments, and finally evaluates the
path- and code-logic result managers to produce the confirmed signatures.

### 4.5 Signature database and managers

The database (`*.sig`) is `Blowfish( gzip( header ‖ sections ) )`. `SigMgr`
loads it by reversing those steps — **decrypt → inflate → verify CRC-32 → parse**
— and validates the `"AAV1"` magic. Each section is `format · count ·
packed/unpacked size · data`, and parsing is **bounds-checked against untrusted
bytes** (running length checks, `memcpy` for unaligned reads, bounded string
scans). The on-disk layout is specified in
[SignatureDbFormat.md](SignatureDbFormat.md).

`DexSigMgr` is a façade over two indexes built once from the loaded database:

- **`DexPathSigMgr`** builds the **`ACTree`** of §3.2 — children sorted on insert
  for binary search, a single owning tree, and failure links computed by
  re-searching the trie — and answers `SearchClassPath` in one walk.
- **`DexCodeSigMgr`** holds the opcode-bitmap pre-filter, the opcode-CRC and
  string-CRC tables (binary-searched), and the code-logic signatures.

Per-file hits accumulate in **`DexPathScanResultMgr`** and
**`DexCodeScanResultMgr`**, which evaluate the §3.4 logic (NOT/XOR veto, AND/OR
affirmative) to yield the confirmed signatures.

### 4.6 Memory-safe DEX parser and modern bytecode

Because it consumes attacker-controlled bytes, the from-scratch parser
(`DexFile` / `DexCode`) is memory-safe by construction: a minimum-size check
before the header copy, `RegionOk` validation of every table offset and size, a
cap on item counts, a **bounded uleb128** decoder, and length-bounded string
reads. It accepts DEX magic **035–040** and walks the **modern opcode family**
(invoke-polymorphic/-custom, const-method-handle/-type). An in-tree libFuzzer
target plus AddressSanitizer/UBSan continuously exercise this path.

The §3.6 bitmap pre-filter, as implemented here, packs the first **8** opcodes
into **4** pairwise 16-bit keys tested against **4** bitmaps of 2¹⁶ bits (**8 KB
each; 32 KB total**), keeping the working set cache-resident.

### 4.7 Parallel scanning

Directory scans parallelize across worker threads (`EngineConfig::scan_threads`).
Targets are enumerated first; each worker owns a private set of scanners
(`FileID`/`ApkScanner`/`DexScanner`) so scanning shares no mutable state. Workers
claim files by atomically incrementing a shared counter (lock-free dynamic load
balancing). The signature database is shared **read-only** (safe without locks
once loaded); the result callback is serialized by a mutex, and each worker's
analysis report is thread-local.

### 4.8 Feature extraction and tooling

Analysis mode (`--analysis`) records, per class, its superclass, source file, and
declared **fields**, and per method its full **prototype** (return type and
parameter descriptors), the opcode- and string-sequence CRC-32s, and the
referenced constant strings — precisely the information a human uses to author a
signature. The bundled `sigtool` generates a self-consistent sample DEX and
signature database so the whole pipeline runs with no external assets; see
[Signatures.md](Signatures.md).

### 4.9 Engineering quality and portability

The engine builds with CMake as both a static and a shared library plus an
installable SDK; miniz is vendored and zlib is required. It targets Linux, macOS,
and Android (NDK, `arm64-v8a`). Quality is enforced by per-module unit tests and
end-to-end tests, AddressSanitizer/UBSan, a libFuzzer harness, line/branch
coverage with a CI floor, and a continuous-integration matrix spanning the three
platforms with dedicated sanitizer, fuzz, coverage, and formatting jobs; the code
follows the Google C++ Style Guide. See [Architecture.md](Architecture.md),
[ObjectModel.md](ObjectModel.md), and [Building.md](Building.md).

---

## 5. Evaluation

> The measurements below were obtained by the reference prototype on the device
> described in §5.1. The published open-source build ships only a synthetic
> sample database and has not been re-measured against a real malware feed, so
> the figures should be read as properties of the method. Full detail and the
> procedure to reproduce them on the current code are in
> [Benchmarks.md](Benchmarks.md).

### 5.1 Methodology and environment

The system was compared against two mainstream commercial mobile detectors —
**Antiy AVL SDK** and **360 Mobile Guards** — along three axes: detection rate,
false-positive rate, and per-file scan time. All three ran on-device on a Huawei
Mate 8 (HiSilicon Kirin 950, 4× Cortex-A72 + 4× Cortex-A53 @ 2.3 GHz, 3 GB RAM,
Android 8.0), scanning the same sample sets from internal storage.

### 5.2 Dataset

| Set | Size | Composition |
| --- | --- | --- |
| Malware | 1000 files | `Android/SmsSpy.ccr` (SMS theft/forgery), 7 variants, from VirusTotal |
| Benign | 100 apps | Legitimate apps from Google Play |
| Signatures | 7 | One authored per variant |

### 5.3 Results

Detection over the malware set and false positives over the benign set:

| Engine | Detection rate | False positives |
| --- | --- | --- |
| **This work** | **99.7%** | **0** |
| Antiy AVL SDK | 98.8% | 0 |
| 360 Mobile Guards | 98.2% | 0 |

Average time to scan one APK:

| Engine | Avg. time / APK | Relative |
| --- | --- | --- |
| **This work** | **71 ms** | 1× |
| Antiy AVL SDK | 355 ms | ~5× slower |
| 360 Mobile Guards | 147 ms | ~2× slower |

### 5.4 Discussion

The method detects about one percentage point more malware than either product,
which we attribute to logic-combined multi-dimensional features generalizing
across variants better than single-feature matching. It matches the commercial
products' zero false-positive rate, confirming that the boolean logic
characterizes behavior precisely. Its 2–5× speed advantage follows directly from
the O(n·log S) design of §3.7 versus the competitors' O(n·S).

### 5.5 Threats to validity

The evaluation corpus is a single malware family across seven variants — narrow
by design for a controlled comparison — so absolute detection numbers may not
generalize to a broad, multi-family feed. The competitors ship much larger
signature databases than the seven-signature test set, so at equal database scale
the absolute time gap would narrow, though the algorithmic-complexity advantage
is independent of database size. Broader, multi-family evaluation on the current
build is left to future work.

---

## 6. Conclusion and Future Work

This thesis characterizes Android malware by the **boolean combination of
multi-dimensional code-behavior fragments**, complemented by **package-path
multi-pattern matching** and a **bitmap method pre-filter**. Together they deliver
accurate, broad-spectrum detection at a whole-file complexity of about
**O(n·log S)**, far below the O(n·S) of typical linear matchers, and — in the
evaluation of Chapter 5 — higher detection, a zero false-positive rate, and 2–5×
faster scanning than two commercial products.

The accompanying implementation is a maintainable, portable, ABI-stable C++17
engine: a memory-safe from-scratch DEX parser (DEX 035–040, modern opcodes,
multidex), a uniform file/memory scan abstraction, RAII ownership, parallel
scanning, and a full testing, fuzzing, coverage, and continuous-integration
apparatus.

Future work includes a real, multi-family signature feed with re-benchmarking of
the current build; additional behavior dimensions (notably system-API-call
sequences, which the combination framework already accommodates); scanners for
ELF/OAT and packed native libraries; incremental database updates; and
integration into a full analysis pipeline (collection, sandbox and ML triage,
human analysis, and feature distribution) so the method and its feature database
co-evolve.

---

## References

1. *Dalvik bytecode and instruction formats.* Android Open Source Project.
   <https://source.android.com/devices/tech/dalvik/dalvik-bytecode.html>
2. *DEX file format.* Android Open Source Project.
   <https://source.android.com/devices/tech/dalvik/dex-format.html>
3. Sun L., Li L. *Improved Aho-Corasick Algorithm for Multiple Patterns Matching
   Memory Efficiency Optimization.* Journal of Convergence Information
   Technology, 2012.
4. Nguyen-Vu L., Ahn J., Jung S. *Android Fragmentation in Malware Detection.*
   Computers & Security, 2019.
5. Amin M. et al. *Static malware detection and attribution in Android byte-code
   through an end-to-end deep system.* Future Generation Computer Systems, 2020.
6. Badhani S., Muttoo S. K. *Analyzing Android Code Graphs against Code
   Obfuscation and App Hiding Techniques.* Journal of Applied Security Research,
   2019.
7. Antiy AVL SDK for Mobile. <https://www.antiy.com/avl-sdk-mobile.html>
8. 360 Mobile Guards. <https://shouji.360.cn/>
9. miniz — single-file ZIP/deflate library. <https://github.com/richgel999/miniz>
10. zlib. <https://zlib.net/>
11. doctest — C++ unit-testing framework. <https://github.com/doctest/doctest>

---

## Provenance

This English edition adapts the Master of Engineering thesis 《一种高效的 Android
恶意代码静态检测系统》 ("An Efficient Android Malware Static Detection System") by
**方阳华 (Yanghua Fang)**, Beijing University of Posts and Telecommunications
(**BUPT**), **2020**; advisor 高占春 (Zhanchun Gao). The detection method and
algorithms are from that work; the architecture and implementation reflect the
current open-source engine in this repository.
