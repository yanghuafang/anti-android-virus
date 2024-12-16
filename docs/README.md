# aav documentation

Guides for using, embedding, and hacking on the **aav** Android malware static
detection engine.

Start with the [project README](../README.md) for a quick build-and-scan, then
pick the topic you need below.

## Concepts

| Document | Contents |
|----------|----------|
| [Thesis.md](Thesis.md) | The full English thesis — method, algorithms, architecture, and evaluation — rewritten to match this implementation |
| [Architecture.md](Architecture.md) | The scan pipeline, engine components, and how the thesis design maps onto the code |
| [ObjectModel.md](ObjectModel.md) | The object/interface hierarchy — the `IStream`/`ITarget` file-vs-memory abstraction, RAII ownership, and namespacing |

## How-to

| Document | Contents |
|----------|----------|
| [Building.md](Building.md) | Build options & presets, install/SDK, testing, sanitizers, fuzzing, and Android/cross-compile |
| [Signatures.md](Signatures.md) | Authoring signatures with `sigtool` and `aavscan --analysis` |

## Reference

| Document | Contents |
|----------|----------|
| [SignatureDbFormat.md](SignatureDbFormat.md) | The on-disk `*.sig` signature-database binary format |

## Evaluation

| Document | Contents |
|----------|----------|
| [Benchmarks.md](Benchmarks.md) | Detection rate, false-positive rate, and scan-speed results from the thesis (vs. Antiy AVL SDK / 360 Mobile Guards) |

## Also

- [../CONTRIBUTING.md](../CONTRIBUTING.md) — build, test, and pull-request workflow
- [../android/README.md](../android/README.md) — the demo Android app + JNI bridge
- [../scripts/README.md](../scripts/README.md) — the helper scripts
