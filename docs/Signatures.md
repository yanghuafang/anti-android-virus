# Authoring signatures

`aav` matches DEX code against a compact **signature database**. This guide
covers producing and inspecting signatures with the bundled tools; the on-disk
layout is documented in [SignatureDbFormat.md](SignatureDbFormat.md).

## Generate the sample database

`sigtool` builds a self-consistent pair — a tiny DEX and a matching signature DB
— so the whole pipeline runs with no external assets:

```bash
sigtool gen-sample <out_dir> [--dex-version NNN]   # NNN in 035..040
# writes <out_dir>/sample.dex and <out_dir>/sample.sig
```

The signature CRCs are computed with the engine's own `Crc32`, so they are
byte-identical to what the scanner produces at runtime.

## Inspect a file's features

To author a signature for a real method you need its fingerprints. Scan with
`--analysis` to print the DEX grouped by class — each class with its superclass,
source file, and declared fields, and under it each method with its full
signature (return type + parameter descriptors, which disambiguate overloads),
the opcode-sequence CRC32, the operand(string)-sequence CRC32, and the
referenced constant strings:

```bash
aavscan --analysis <signature-db> <apk|dex>
```

On the bundled sample this prints both classes with `Worker`'s fields and
methods — note the virtual `run(I)V` shows the parameter that disambiguates
overloads:

```
  analysis: 2 class(es)
    class com.aav.sample.evil : V
    class com.aav.sample.worker : V
      static field sCount : I
      field count : I
      method work()V  [known]
        opcodeCRC32:  0x280b656c
        operandCRC32: 0x90a9e0a8
          "evilpayload"
      virtual method run(I)V
```

The CRCs are exactly the values a `DEX_OPCODE_CRC` / `DEX_OPERAND_CRC`
signature is built from. They can be combined with AND/OR/XOR/NOT logic
(`DEX_CODE_LOGIC`) and a class-path signature (`DEX_PATH`); see
[SignatureDbFormat.md](SignatureDbFormat.md) for how the sections fit together.

## Notes

- The database is **Blowfish-obfuscated + gzip-compressed** and carries the
  magic `"AAV1"`; the loader rejects any other magic. The Blowfish key is a
  fixed, shared secret baked into both the engine and `sigtool`, so it provides
  obfuscation/tamper-evidence, **not** real confidentiality.
- The bundled DB is a **synthetic sample**, not a real malware feed. Regenerate
  it with `sigtool` whenever the DB format changes.
