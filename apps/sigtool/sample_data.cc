#include "sample_data.h"

#include <zlib.h>

#include <cstring>

#include "aav/sig_format.h"    // SigFormat
#include "blowfish.h"          // Blowfish
#include "crc32.h"             // aav::Crc32
#include "dex_sig.h"           // STR/LOGIC match types, kBitMapSize
#include "malware_name.h"      // MalwareName / MalwareFamily / SigName
#include "sig_db_structure.h"  // SigHeader / SigSectionHeader / kSigMagic

namespace aav {
namespace sample {

namespace {

static const char kBlowfishKey[] = "aav-dex-malware-signature-db-v1";
static const uint32_t kNameId = 1;
static const uint32_t kFamilyId = 1;

// Little-endian byte-buffer helpers.
void Put8(Bytes& b, uint8_t v) { b.push_back(v); }
void Put16(Bytes& b, uint16_t v) {
  b.push_back(static_cast<uint8_t>(v & 0xff));
  b.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
}
void Put32(Bytes& b, uint32_t v) {
  for (int i = 0; i < 4; ++i)
    b.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xff));
}
void PutBytes(Bytes& b, const void* p, size_t n) {
  const uint8_t* q = static_cast<const uint8_t*>(p);
  b.insert(b.end(), q, q + n);
}
void PutStrZ(Bytes& b, const std::string& s) {
  PutBytes(b, s.data(), s.size());
  b.push_back(0);
}
void PutUleb(Bytes& b, uint32_t v) {
  do {
    uint8_t byte = v & 0x7f;
    v >>= 7;
    if (v) byte |= 0x80;
    b.push_back(byte);
  } while (v);
}
void Patch32(Bytes& b, size_t pos, uint32_t v) {
  for (int i = 0; i < 4; ++i)
    b[pos + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
}
void Align4(Bytes& b) {
  while (b.size() % 4) b.push_back(0);
}

// Feature CRC using the engine's crc32 (guarantees parity with the scanner).
uint32_t MemCrc(const void* buf, int len) {
  return Crc32(0, buf, static_cast<uint32_t>(len));
}

static const char kEvilType[] = "Lcom/aav/sample/Evil;";
static const char kWorkerType[] = "Lcom/aav/sample/Worker;";
static const char kConstString[] = "evilpayload";

// Opcode buffer DexCode::ParseCode produces for Worker.work().
static const uint8_t kOpcodeBuf[] = {0x12, 0x12, 0x12, 0x1a,
                                     0x00, 0x00, 0x00, 0x0e};
static const uint16_t kFast01 = 0x1212;
static const uint16_t kFast23 = 0x1a12;
static const uint16_t kFast45 = 0x0000;
static const uint16_t kFast67 = 0x0e00;

void AddSection(Bytes& out, uint32_t format, uint32_t sig_count,
                const Bytes& data) {
  Put32(out, format);
  Put32(out, sig_count);
  Put32(out, static_cast<uint32_t>(data.size()));  // packedSize
  Put32(out, static_cast<uint32_t>(data.size()));  // unpackedSize
  out.insert(out.end(), data.begin(), data.end());
}

// Split "com.aav.sample.evil" -> per-segment CRC32 (matches DexPathSigMgr).
std::vector<uint32_t> PathSegmentCrcs(const std::string& dotted_lower) {
  std::vector<uint32_t> crcs;
  size_t start = 0;
  for (size_t i = 0; i <= dotted_lower.size(); ++i) {
    if (i == dotted_lower.size() || dotted_lower[i] == '.') {
      if (i > start)
        crcs.push_back(
            MemCrc(dotted_lower.data() + start, static_cast<int>(i - start)));
      start = i + 1;
    }
  }
  return crcs;
}

Bytes GzipCompress(const Bytes& in) {
  z_stream s;
  memset(&s, 0, sizeof(s));
  deflateInit2(&s, Z_BEST_COMPRESSION, Z_DEFLATED, 16 + MAX_WBITS, 8,
               Z_DEFAULT_STRATEGY);
  s.next_in = const_cast<Bytef*>(in.data());
  s.avail_in = static_cast<uInt>(in.size());
  Bytes out;
  uint8_t buf[16384];
  int ret;
  do {
    s.next_out = buf;
    s.avail_out = sizeof(buf);
    ret = deflate(&s, Z_FINISH);
    out.insert(out.end(), buf, buf + (sizeof(buf) - s.avail_out));
  } while (ret != Z_STREAM_END);
  deflateEnd(&s);
  return out;
}

}  // namespace

// A well-formed DEX with two classes:
//   Evil    -- matches the class-path signature (kPathSigId).
//   Worker  -- work() (direct) matches the code signature (kCodeSigId); run(I)V
//              (virtual) carries a declared field pair, a parameter, a modern
//              (DEX 039) const-method-handle opcode and a fill-array-data
//              payload, so the whole feature surface (--analysis fields /
//              virtual methods / parameters, plus the parser's modern-opcode
//              and inline-payload paths) is exercised by a single generated
//              sample.
// work()'s bytecode is kept byte-identical to what BuildSampleSig hashes, so
// the two signatures still fire.
Bytes BuildSampleDex(const std::string& version) {
  Bytes d;
  d.resize(0x70, 0);  // header placeholder

  const uint32_t k_num_strings = 10;
  const uint32_t off_string_ids = static_cast<uint32_t>(d.size());
  const size_t pos_string_ids = d.size();
  d.resize(d.size() + k_num_strings * 4, 0);

  const uint32_t off_type_ids = static_cast<uint32_t>(d.size());
  Put32(d, 0);  // t0 -> "Lcom/aav/sample/Evil;"
  Put32(d, 1);  // t1 -> "Lcom/aav/sample/Worker;"
  Put32(d, 2);  // t2 -> "V"
  Put32(d, 5);  // t3 -> "I"

  const uint32_t off_proto_ids = static_cast<uint32_t>(d.size());
  Put32(d, 2);  // p0 shorty_idx -> "V"
  Put32(d, 2);  // p0 return_type_idx -> t2 (V)
  Put32(d, 0);  // p0 parameters_off (none)
  Put32(d, 9);  // p1 shorty_idx -> "VI"
  Put32(d, 2);  // p1 return_type_idx -> t2 (V)
  Put32(d, 0);  // p1 parameters_off (patched -> type_list below)
  const size_t pos_p1_params_off = off_proto_ids + 12 + 8;

  const uint32_t off_field_ids = static_cast<uint32_t>(d.size());
  Put16(d, 1);
  Put16(d, 3);
  Put32(d, 6);  // f0: Worker.sCount : I  (static)
  Put16(d, 1);
  Put16(d, 3);
  Put32(d, 7);  // f1: Worker.count  : I  (instance)

  const uint32_t off_method_ids = static_cast<uint32_t>(d.size());
  Put16(d, 1);
  Put16(d, 0);
  Put32(d, 3);  // m0: Worker.work ()V
  Put16(d, 1);
  Put16(d, 1);
  Put32(d, 8);  // m1: Worker.run  (I)V

  const uint32_t off_class_defs = static_cast<uint32_t>(d.size());
  const size_t pos_class_defs = d.size();
  d.resize(d.size() + 2 * 32, 0);

  const char* strings[k_num_strings] = {
      kEvilType, kWorkerType, "V",     "work", kConstString,
      "I",       "sCount",    "count", "run",  "VI"};
  uint32_t str_off[k_num_strings];
  for (uint32_t i = 0; i < k_num_strings; ++i) {
    str_off[i] = static_cast<uint32_t>(d.size());
    PutUleb(d, static_cast<uint32_t>(strlen(strings[i])));
    PutStrZ(d, strings[i]);
  }

  // type_list for p1's parameters: (I)
  Align4(d);
  const uint32_t off_type_list = static_cast<uint32_t>(d.size());
  Put32(d, 1);  // size
  Put16(d, 3);  // type_idx -> t3 (I)

  const uint32_t evil_class_data_off = static_cast<uint32_t>(d.size());
  PutUleb(d, 0);  // static_fields_size
  PutUleb(d, 0);  // instance_fields_size
  PutUleb(d, 0);  // direct_methods_size
  PutUleb(d, 0);  // virtual_methods_size

  Align4(d);
  const uint32_t code_off = static_cast<uint32_t>(d.size());  // work()
  Put16(d, 1);       // registers_size (v0)
  Put16(d, 0);       // ins_size
  Put16(d, 0);       // outs_size
  Put16(d, 0);       // tries_size
  Put32(d, 0);       // debug_info_off
  Put32(d, 9);       // insns_size (code units)
  Put16(d, 0x0012);  // const/4 v0, #0
  Put16(d, 0x0012);
  Put16(d, 0x0012);
  Put16(d, 0x001a);  // const-string v0, string@...
  Put16(d, 0x0004);  //   string index = 4 ("evilpayload")
  Put16(d, 0x0000);  // nop
  Put16(d, 0x0000);
  Put16(d, 0x0000);
  Put16(d, 0x000e);  // return-void

  Align4(d);
  const uint32_t run_code_off = static_cast<uint32_t>(d.size());  // run(I)V
  Put16(d, 3);       // registers_size
  Put16(d, 2);       // ins_size (this + I)
  Put16(d, 0);       // outs_size
  Put16(d, 0);       // tries_size
  Put32(d, 0);       // debug_info_off
  Put32(d, 11);      // insns_size (code units)
  Put16(d, 0x0012);  // const/4 v0, #0
  Put16(d, 0x00fe);  // const-method-handle v0, method_handle@0  (DEX 039)
  Put16(d, 0x0000);  //   method_handle index
  Put16(d, 0x0026);  // fill-array-data v0, +BBBBBBBB
  Put16(d, 0x0003);  //   branch offset low (3 code units from here -> payload)
  Put16(d, 0x0000);  //   branch offset high
  Put16(d, 0x0300);  // payload: ident
  Put16(d, 0x0001);  //   element_width = 1
  Put16(d, 0x0001);  //   size low
  Put16(d, 0x0000);  //   size high
  Put16(d, 0x0000);  //   1 byte of data (padded to a code unit)

  const uint32_t worker_class_data_off = static_cast<uint32_t>(d.size());
  PutUleb(d, 1);  // static_fields_size
  PutUleb(d, 1);  // instance_fields_size
  PutUleb(d, 1);  // direct_methods_size
  PutUleb(d, 1);  // virtual_methods_size
  PutUleb(d, 0);
  PutUleb(d, 0x8);  // static field f0 (diff 0), ACC_STATIC
  PutUleb(d, 1);
  PutUleb(d, 0x2);  // instance field f1 (diff 1), ACC_PRIVATE
  PutUleb(d, 0);
  PutUleb(d, 0x1);
  PutUleb(d, code_off);  // direct m0 work
  PutUleb(d, 1);
  PutUleb(d, 0x1);
  PutUleb(d, run_code_off);  // virtual m1 run

  const uint32_t total = static_cast<uint32_t>(d.size());

  for (uint32_t i = 0; i < k_num_strings; ++i)
    Patch32(d, pos_string_ids + i * 4, str_off[i]);
  Patch32(d, pos_p1_params_off, off_type_list);

  auto write_class_def = [&](size_t pos, uint32_t class_idx,
                             uint32_t class_data_off) {
    Patch32(d, pos + 0, class_idx);
    Patch32(d, pos + 4, 0x1);
    Patch32(d, pos + 8, 2);  // superclass_idx -> t2
    Patch32(d, pos + 12, 0);
    Patch32(d, pos + 16, 0xffffffff);  // source_file_idx (NO_INDEX)
    Patch32(d, pos + 20, 0);
    Patch32(d, pos + 24, class_data_off);
    Patch32(d, pos + 28, 0);
  };
  write_class_def(pos_class_defs + 0, 0, evil_class_data_off);     // Evil
  write_class_def(pos_class_defs + 32, 1, worker_class_data_off);  // Worker

  uint8_t k_magic[8] = {0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00};
  k_magic[4] = static_cast<uint8_t>(version.size() > 0 ? version[0] : '0');
  k_magic[5] = static_cast<uint8_t>(version.size() > 1 ? version[1] : '3');
  k_magic[6] = static_cast<uint8_t>(version.size() > 2 ? version[2] : '5');
  memcpy(d.data(), k_magic, 8);
  Patch32(d, 32, total);          // file_size
  Patch32(d, 36, 0x70);           // header_size
  Patch32(d, 40, 0x12345678);     // endian_tag
  Patch32(d, 56, k_num_strings);  // string_ids_size
  Patch32(d, 60, off_string_ids);
  Patch32(d, 64, 4);  // type_ids_size
  Patch32(d, 68, off_type_ids);
  Patch32(d, 72, 2);  // proto_ids_size
  Patch32(d, 76, off_proto_ids);
  Patch32(d, 80, 2);  // field_ids_size
  Patch32(d, 84, off_field_ids);
  Patch32(d, 88, 2);  // method_ids_size
  Patch32(d, 92, off_method_ids);
  Patch32(d, 96, 2);  // class_defs_size
  Patch32(d, 100, off_class_defs);
  Patch32(d, 104, total - off_class_defs);  // data_size (approx)
  Patch32(d, 108, off_class_defs);          // data_off (approx)
  return d;
}

Bytes BuildSampleSig() {
  const uint32_t opcode_crc =
      MemCrc(kOpcodeBuf, static_cast<int>(sizeof(kOpcodeBuf)));
  Bytes operand;
  PutBytes(operand, kConstString, strlen(kConstString));
  operand.push_back(0);
  const uint32_t operand_crc =
      MemCrc(operand.data(), static_cast<int>(operand.size()));
  const std::vector<uint32_t> seg_crcs = PathSegmentCrcs("com.aav.sample.evil");

  Bytes sections;

  {
    Bytes t;
    PutStrZ(t, "Trojan");
    AddSection(sections, kSigFormatType, 1, t);
  }
  {
    Bytes f;  // MalwareFamily {id}{name\0}, 4-aligned
    Put32(f, kFamilyId);
    PutStrZ(f, "SampleFam");
    while (f.size() % 4) f.push_back(0);
    AddSection(sections, kSigFormatFamily, 1, f);
  }
  {
    Bytes v;
    PutStrZ(v, "a");
    AddSection(sections, kSigFormatVariant, 1, v);
  }
  {
    Bytes p;
    PutStrZ(p, "Android");
    AddSection(sections, kSigFormatPlatform, 1, p);
  }
  {
    Bytes ff;
    PutStrZ(ff, "Dex");
    AddSection(sections, kSigFormatFileFormat, 1, ff);
  }
  {
    Bytes n;              // MalwareName (16 bytes)
    Put32(n, kNameId);    // id
    Put8(n, 0);           // type -> "Trojan"
    Put8(n, 0);           // reserve
    Put8(n, 0);           // platform -> "Android"
    Put8(n, 0);           // file_format -> "Dex"
    Put32(n, kFamilyId);  // family
    Put32(n, 0);          // variant -> "a"
    AddSection(sections, kSigFormatName, 1, n);
  }
  {
    Bytes sig;  // SigName[]: sig_id -> name_id
    Put32(sig, kPathSigId);
    Put32(sig, kNameId);
    Put32(sig, kCodeSigId);
    Put32(sig, kNameId);
    AddSection(sections, kSigFormatSig, 2, sig);
  }

  {  // DEX path signature (EQUAL, OR)
    Bytes p;
    Put32(p, kPathSigId);
    Put8(p, static_cast<uint8_t>(kStrMatchTypeEqual));
    Put8(p, static_cast<uint8_t>(kLogicMatchTypeOr));
    Put16(p, static_cast<uint16_t>(seg_crcs.size()));
    for (uint32_t c : seg_crcs) Put32(p, c);
    AddSection(sections, kSigFormatDexPath, 1, p);
  }

  {  // DEX opcode bitmap (4 maps x 8192 bytes), one entry per map
    const int map_bytes = kBitMapSize / 8;  // 8192
    Bytes maps(map_bytes * 4, 0);
    auto set_bit = [&](int map_index, uint16_t v) {
      maps[map_index * map_bytes + (v >> 3)] |=
          static_cast<uint8_t>(1u << (v & 7));
    };
    set_bit(0, kFast01);
    set_bit(1, kFast23);
    set_bit(2, kFast45);
    set_bit(3, kFast67);
    AddSection(sections, kSigFormatDexOpcodeMap, 4, maps);
  }

  {  // DEX opcode-sequence CRC -> code sig
    Bytes c;
    Put32(c, opcode_crc);
    Put32(c, 1);  // sig_id_count
    Put32(c, kCodeSigId);
    AddSection(sections, kSigFormatDexOpcodeCrc, 1, c);
  }

  {  // DEX operand(string)-sequence CRC -> code sig
    Bytes c;
    Put32(c, operand_crc);
    Put32(c, 1);
    Put32(c, kCodeSigId);
    AddSection(sections, kSigFormatDexOperandCrc, 1, c);
  }

  {  // DEX code logic: AND(opcodeCrc, operandCrc) confirms the malware
    Bytes l;
    Put32(l, kCodeSigId);
    Put32(l, 0);  // not_crcs count
    Put32(l, 0);  // xor_crcs count
    Put32(l, 2);  // and_crcs count
    Put32(l, opcode_crc);
    Put32(l, operand_crc);
    Put32(l, 0);  // or_crcs count
    AddSection(sections, kSigFormatDexCodeLogic, 1, l);
  }

  // Header crc over sections (zlib crc32, matches SigMgr).
  uint32_t crc = static_cast<uint32_t>(crc32(0L, Z_NULL, 0));
  crc = static_cast<uint32_t>(
      crc32(crc, sections.data(), static_cast<uInt>(sections.size())));

  Bytes plain;
  Put32(plain, kSigMagic);  // magic "AAV1"
  Put32(plain, 1);          // version
  Put32(plain, 0);          // timestamp
  Put32(plain, crc);        // crc of sections
  plain.insert(plain.end(), sections.begin(), sections.end());

  Bytes gz = GzipCompress(plain);

  Blowfish bf;
  bf.SetKey(std::string(kBlowfishKey));
  std::string gz_str(gz.begin(), gz.end());
  std::string enc;
  bf.Encrypt(&enc, gz_str);
  return Bytes(enc.begin(), enc.end());
}

}  // namespace sample
}  // namespace aav
