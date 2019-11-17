# Signature database format (`*.sig`)

This document specifies the on-disk format of the `aav` signature database — the
`*.sig` file that `aavscan` loads and `sigtool` produces. It is the source of
truth for anyone building a real signature feed.

All integers are **little-endian**. All structures are **byte-packed**
(`#pragma pack(1)`) unless a section explicitly pads. The authoritative struct
definitions live in `src/sig/sig_db_structure.h`, `src/api/aav/sig_format.h`,
`src/sig/malware_name.h`, and `src/dex/dex_sig.h`; the reference writer is
`apps/sigtool/sigtool.cc` and the reference reader is `src/sig/sig_mgr.cc`.

## On-disk envelope

The file is the payload wrapped in gzip and then Blowfish:

```
file  =  Blowfish_encrypt( gzip( payload ),  key = "aav-dex-malware-signature-db-v1" )
payload = SigHeader  ||  section_0 || section_1 || ... || section_n
```

To read it, the engine reverses the steps: **Blowfish-decrypt → gzip-inflate →
verify CRC → parse header + sections** (`SigMgr::CheckAndLoadSigs`).

> The Blowfish key is a fixed, shared secret baked into both the engine and
> `sigtool`. It provides obfuscation/tamper-evidence, **not** real
> confidentiality.

## Header — `SigHeader` (16 bytes)

| Offset | Type   | Field       | Notes                                             |
| ------ | ------ | ----------- | ------------------------------------------------- |
| 0      | u32    | `magic`     | `"AAV1"` (bytes `41 41 56 31`)                    |
| 4      | u32    | `version`   | currently `1`                                     |
| 8      | u32    | `timestamp` | build time (unix seconds); `0` in samples         |
| 12     | u32    | `crc`       | zlib `crc32` over the concatenated section bytes  |

## Sections

The header is followed by a sequence of sections. Each section is a
`SigSectionHeader` (16 bytes) followed by `packedSize` bytes of payload:

| Offset | Type | Field          | Notes                                             |
| ------ | ---- | -------------- | ------------------------------------------------- |
| 0      | u32  | `format`       | a `SigFormat` value (see below)                 |
| 4      | u32  | `sigCount`     | number of records in this section                 |
| 8      | u32  | `packedSize`   | payload size on disk                              |
| 12     | u32  | `unpackedSize` | payload size after (optional) per-section unpack   |

In the current engine and `sigtool`, sections are stored uncompressed, so
`packedSize == unpackedSize`. The section stream ends at end-of-payload.

### `SigFormat` values

```
UNKNOWN        = 0
# Naming
TYPE           = 10   FAMILY   PLATFORM   FILE_FORMAT   VARIANT   NAME   SIG   (10..16)
AdInfo         = 20
# DEX
DEX_PATH       = 30   DexOpcodeMapRaw   DEX_OPCODE_CRC   DEX_OPERAND_CRC   DEX_CODE_LOGIC (30..34)
# Reserved (not implemented): ELF=40.., OAT=50.., MACHO=60.., PE=70.., WHITE_*=80..
```

## Naming sections

These map the numeric `sig_id` produced by matching to a readable name string
`Type!Family.variant@Platform.FileFormat` (e.g. `Trojan!SampleFam.a@Android.Dex`).

- **`TYPE` / `VARIANT` / `PLATFORM` / `FILE_FORMAT`** — `sigCount` NUL-terminated
  strings, concatenated. A record's index (0-based) is what other sections refer
  to (e.g. `MALWARE_NAME.type` indexes the `TYPE` list).
- **`FAMILY`** — `MALWARE_FAMILY` records `{ id:u32 }{ name:cstr }`, each padded
  to a 4-byte boundary.
- **`NAME`** — `MALWARE_NAME[]`, 16 bytes each:
  `{ id:u32, type:u8, reserve:u8, platform:u8, file_format:u8, family:u32, variant:u32 }`.
- **`SIG`** — `SIG_NAME[]` pairs `{ sig_id:u32 }{ name_id:u32 }` mapping a matched
  signature id to a `MALWARE_NAME.id`.

## DEX signature sections

### `DEX_PATH` — class-path signatures
`DexPathSigRaw[]`, each:

```
{ sig_id:u32 } { str_match_type:u8 } { logic_match_type:u8 }
{ path_max_layer:u16 } { path_crcs: path_max_layer × u32 }
```

`path_crcs[i]` is `crc32` of the i-th `.`-separated, lower-cased segment of the
class path (matched by the Aho–Corasick trie). `str_match_type` ∈
`STR_MATCH_TYPE` (EQUAL / START_WITH / END_WITH / CONTAIN); `logic_match_type` ∈
`LOGIC_MATCH_TYPE` (AND / OR / XOR / NOT).

### `DexOpcodeMapRaw` — opcode bitmap pre-filter
Four bitmaps of `BIT_MAP_SIZE` (65536) bits each = `4 × 8192` bytes, stored
back-to-back (`sigCount = 4`). Map *k* has bit *v* set iff the method's *k*-th
"fast opcode" 16-bit value *v* is allowed; the scanner uses it to cheaply skip
methods that cannot match before computing CRCs.

### `DEX_OPCODE_CRC` / `DEX_OPERAND_CRC` — code CRC signatures
`DexCodeCrcSigRaw[]`, each:

```
{ crc:u32 } { sig_id_count:u32 } { sig_ids: sig_id_count × u32 }
```

`crc` is `crc32` of a method's opcode buffer (`DEX_OPCODE_CRC`) or of its
operand/string buffer (`DEX_OPERAND_CRC`); it maps to one or more `sig_id`s.

### `DEX_CODE_LOGIC` — boolean combination
`DexCodeLogicSigRaw[]`, each is a `sig_id` followed by four `DexLogicCrcsRaw` blocks
in the order NOT, XOR, AND, OR:

```
{ sig_id:u32 }
{ not_crcs:  DexLogicCrcsRaw }
{ xor_crcs:  DexLogicCrcsRaw }
{ and_crcs:  DexLogicCrcsRaw }
{ or_crcs:   DexLogicCrcsRaw }

DexLogicCrcsRaw = { crc_count:u32 } { crcs: crc_count × u32 }
```

The `sig_id` is considered matched when the boolean expression over the code
CRCs collected from the file evaluates true — e.g. `AND(opcodeCrc, operandCrc)`
requires both fingerprints to be present.

## CRC conventions

The project has a single CRC-32 implementation (`aav::Crc32`, ISO-HDLC /
reflected, poly `0xEDB88320`), which is bit-for-bit identical to zlib's `crc32`.

- **Feature CRCs** (path segments, opcode buffers, operand buffers) use
  `aav::Crc32` (`src/utils/crc32.*`), so a DB built with `sigtool` is
  byte-identical to what the scanner computes at runtime.
- **The header `crc`** field covers the raw section bytes: `sigtool` stamps it
  with zlib's `crc32` and the engine verifies it with `aav::Crc32` — the same
  value, since the two are identical.

## Worked example

`sigtool gen-sample` emits a DB with: the six naming sections + `SIG`; one
`DEX_PATH` signature over `com.aav.sample.evil` (id `1001`); a `DexOpcodeMapRaw`;
one `DEX_OPCODE_CRC` and one `DEX_OPERAND_CRC` (both → id `1002`); and one
`DEX_CODE_LOGIC` that confirms id `1002` via `AND(opcodeCrc, operandCrc)`.
Scanning the matching `sample.dex` yields both `1001` and `1002`, resolved to
`Trojan!SampleFam.a@Android.Dex`. See `sigtool.cc` for the exact bytes.
