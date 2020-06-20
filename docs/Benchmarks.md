# Benchmarks

This is the detailed companion to **Chapter 5 ("Evaluation" / 测试与评估)** of the
project [thesis](Thesis.md), *"An Efficient Android Malware Static Detection
System"* — adapted from the master's thesis 《一种高效的 Android 恶意代码静态检测
系统》 by 方阳华 (Yanghua Fang), Beijing University of Posts and Telecommunications
(BUPT), 2020. The prototype was compared head-to-head against two mainstream
Chinese mobile AV products — **Antiy AVL SDK** and **360 Mobile Guards (360 手机
卫士)** — along three axes: detection rate, false-positive rate, and scan speed.

> **Scope / honesty note.** The numbers below were measured by the **original
> 2020 prototype** on a specific device. This repository is a clean-room
> *modernization* of that engine and ships only a **synthetic** sample signature
> database (see [Signatures.md](Signatures.md)), so it has **not** been
> re-benchmarked against a real malware feed. The figures are reproduced here
> for reference and to document the method's design goals; treat them as
> properties of the algorithm, not of the current build. See
> [Reproducing](#reproducing) for how you'd measure the current code.

## Test environment

| | |
| --- | --- |
| Device | Huawei Mate 8 |
| SoC | HiSilicon Kirin 950 — 4× Cortex-A72 + 4× Cortex-A53 @ 2.3 GHz |
| RAM / storage | 3 GB / 32 GB |
| OS | Android 8.0 |
| Setup | Samples on internal storage; all three engines run on-device |

## Dataset

| Set | Size | Composition |
| --- | --- | --- |
| Malware | 1000 files | `Android/SmsSpy.ccr` (SMS theft/forgery), 7 variants, randomly pulled from VirusTotal |
| Benign | 100 apps | Legitimate apps from Google Play |
| Signatures | 7 | One extracted per variant (via this engine's feature extractor) |

The malware corpus is a **single family across 7 variants** — narrow by design
for a proof-of-concept. The [thesis](Thesis.md) (Chapter 6) explicitly calls out
this limited breadth/depth as future work; broader, multi-family evaluation
remains open.

## Detection effectiveness

Malware set (1000 samples) and benign set (100 apps):

| Engine | Detected | Detection rate | False positives (benign) |
| --- | --- | --- | --- |
| **aav (this work)** | 998 | **99.7%** | **0 (0%)** |
| Antiy AVL SDK | 988 | 98.8% | 0 (0%) |
| 360 Mobile Guards | 982 | 98.2% | 0 (0%) |

- ~1 percentage point higher detection than both products — attributed to the
  multi-dimensional **logic-combination** signatures generalizing across variants
  better than single-dimension matching.
- **Zero false positives** for all three engines on the benign set: the
  AND/OR/XOR/NOT feature logic characterizes behavior precisely enough to match
  the very low FPR of shipping commercial products.

## Scan performance

Average time to scan one APK:

| Engine | Avg time / APK | aav is… |
| --- | --- | --- |
| **aav (this work)** | **71 ms** | — |
| Antiy AVL SDK | 355 ms | ~5.0× faster |
| 360 Mobile Guards | 147 ms | ~2.1× faster |

Total wall-clock time to scan the full 1000-sample malware set (thesis Fig. 5-2)
was **713 s / 3550 s / 1477 s** respectively — the same ~5× and ~2× ratios.
(Both the per-APK and per-set figures are reproduced exactly as reported in the
thesis.)

**Why it's faster.** Whole-file scan complexity is **O(N·log N)** versus the
**O(N²)** of most competitors, from three design choices (detailed in the
[thesis](Thesis.md) §3–§4):

- **Package-path matching** via an Aho-Corasick–variant trie keyed on segment
  CRC32s — O(log N) per lookup instead of O(N) linear signature matching
  (thesis §3.2).
- **Logic-combination code signatures** matched through sorted CRC tables
  (binary search), also O(log N) (thesis §3.4).
- A **fast-opcode Bitmap pre-filter** (O(1)) that skips methods no signature
  could match before any CRCs are computed (thesis §3.6; the current
  implementation uses 8 opcodes → 4 keys → 4 × 8 KB bitmaps, see §4.6).

Caveat from the thesis: the two competitors ship **much larger** signature
databases than the 7-signature test DB, so at equal DB scale the absolute gap
would narrow somewhat — but the algorithmic complexity advantage stands.

## Conclusion (thesis §5.4)

Against Antiy AVL SDK and 360 Mobile Guards, the method achieves **higher
detection**, an **equally low (zero) false-positive rate**, and **2–5× faster**
scanning — validating that multi-dimensional logic-combination features
represent malware behavior more accurately and flexibly while keeping scan cost
low.

## Reproducing

The shipped sample DB only detects a synthetic sample, so it can't reproduce the
numbers above. To benchmark the current engine on your own corpus:

1. Build a signature database from a labeled sample set (see
   [Signatures.md](Signatures.md); `sigtool` generates the bundled sample, and is
   the starting point for a real feed).
2. Time a directory scan, single- and multi-threaded:

   ```bash
   time aavscan <your.sig> /path/to/samples          # single-threaded
   time aavscan --mt 8 <your.sig> /path/to/samples   # 8 worker threads
   ```

3. For detection/FPR, run over labeled malware and benign directories and
   compare the callback verdicts against ground truth.

See the [thesis](Thesis.md) for the full method and architecture,
[Building.md](Building.md) for build options, and
[Architecture.md](Architecture.md) for how the pipeline produces these results.
