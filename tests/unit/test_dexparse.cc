#include <fcntl.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "aav/factory.h"
#include "aav/mem_source.h"
#include "aav/mem_target_interface.h"
#include "aav/object_interface.h"
#include "aav/object_ptr.h"
#include "crc32.h"
#include "dex_analysis.h"  // SetDexAnalysisEnabled
#include "dex_code.h"
#include "dex_code_sig_mgr.h"  // FastOpcodes
#include "dex_file.h"
#include "doctest.h"

using namespace aav;

// Drive the DEX parser over a buffer. It must never read out of bounds — this
// is asserted hard by the `asan` build (ASan/UBSan). Here we just require that
// it returns without crashing or hanging.
static void DriveDex(std::vector<uint8_t>& buf) {
  if (buf.size() < 0x70) return;
  aav::ObjPtr<IMemTarget> target = aav::MakeMemtarget();
  if (!target) return;
  MemSource src;
  src.mode = O_RDONLY;
  src.name = "t.dex";
  src.buf = buf.data();
  src.buf_size = static_cast<int>(buf.size());
  if (0 == target->Init(&src)) {
    DexFile df;
    if (0 == df.Init(target.get())) {
      // Enable analysis so the index-based info accessors (GetProtoInfo etc.)
      // run on this input; their bounds are ASan-checked here.
      const bool prev = IsDexAnalysisEnabled();
      SetDexAnalysisEnabled(true);
      std::string cls;
      int r;
      int guard = 0;
      while (-1 != (r = df.GetClass(cls)) && guard++ < 10000) {
        if (r == -2) continue;
        ClassInfo ci;
        df.GetCurrentClassInfo(ci);
        std::vector<FieldInfo> class_fields;
        df.GetCurrentClassFields(class_fields);
        std::string m, p;
        DexCode code;
        uint32_t key = 0;
        int g2 = 0;
        while (-1 != (r = df.GetDirectMethod(m, p, code, key)) &&
               g2++ < 10000) {
          if (r == -2) continue;
          MethodInfo mi;
          df.GetMethodInfo(key, mi);
          FastOpcodes fo;
          code.GetFastOpcodes(fo);
          code.ParseCode();
        }
        key = 0;
        g2 = 0;
        while (-1 != (r = df.GetVirtualMethod(m, p, code, key)) &&
               g2++ < 10000) {
          if (r == -2) continue;
          MethodInfo mi;
          df.GetMethodInfo(key, mi);
          FastOpcodes fo;
          code.GetFastOpcodes(fo);
          code.ParseCode();
        }
      }
      // Hit the index-based accessors directly over a range that includes
      // out-of-range indices, so the hardened bounds are exercised.
      for (uint32_t idx = 0; idx < 260; ++idx) {
        ProtoInfo pi;
        df.GetProtoInfo(idx, pi);
        FieldInfo fi;
        df.GetFieldInfo(idx, fi);
        MethodInfo mi;
        df.GetMethodInfo(idx, mi);
        ClassInfo ci;
        df.GetClassInfo(idx, ci);
      }
      SetDexAnalysisEnabled(prev);
    }
  }
}

static void Put32(std::vector<uint8_t>& b, size_t o, uint32_t v) {
  b[o + 0] = static_cast<uint8_t>(v);
  b[o + 1] = static_cast<uint8_t>(v >> 8);
  b[o + 2] = static_cast<uint8_t>(v >> 16);
  b[o + 3] = static_cast<uint8_t>(v >> 24);
}

static void StampHeader(std::vector<uint8_t>& b) {
  static const uint8_t magic[8] = {0x64, 0x65, 0x78, 0x0a,
                                   0x30, 0x33, 0x35, 0x00};
  memcpy(b.data(), magic, 8);
  Put32(b, 32, static_cast<uint32_t>(b.size()));  // file_size
  Put32(b, 36, 0x70);                             // header_size
  Put32(b, 40, 0x12345678);                       // endian_tag
}

TEST_CASE("DexFile: header-only buffer parses to zero classes") {
  std::vector<uint8_t> b(0x70, 0);
  StampHeader(b);
  DriveDex(b);
  CHECK(true);
}

TEST_CASE("DexFile: sub-header-size buffer is rejected without over-read") {
  // A buffer shorter than the 0x70-byte header must be rejected before the
  // header memcpy, which would otherwise over-read (ASan-checked here). This is
  // the reachable path for a tiny classes.dex inside a crafted APK.
  for (size_t n : {size_t{1}, size_t{8}, size_t{16}, size_t{0x6f}}) {
    std::vector<uint8_t> b(n, 0);
    aav::ObjPtr<IMemTarget> target = aav::MakeMemtarget();
    REQUIRE(target);
    MemSource src;
    src.mode = O_RDONLY;
    src.name = "t.dex";
    src.buf = b.data();
    src.buf_size = static_cast<int>(n);
    if (0 != target->Init(&src)) continue;
    DexFile df;
    CHECK(0 != df.Init(target.get()));
  }
}

TEST_CASE("DexFile: out-of-range table size/offset is rejected, not read") {
  std::vector<uint8_t> b(0x80, 0);
  StampHeader(b);
  Put32(b, 56, 0x7fffffff);  // string_ids_size (huge)
  Put32(b, 60, 0x70);        // string_ids_off
  DriveDex(b);
  CHECK(true);
}

TEST_CASE("DexFile: bogus class_data / code offsets do not read OOB") {
  std::vector<uint8_t> b(0x100, 0);
  StampHeader(b);
  Put32(b, 96, 1);      // class_defs_size = 1
  Put32(b, 100, 0x70);  // class_defs_off
  // class_def_item at 0x70: class_idx=0, ..., class_data_off = near EOF
  Put32(b, 0x70 + 24, static_cast<uint32_t>(b.size() - 2));  // class_data_off
  DriveDex(b);
  CHECK(true);
}

TEST_CASE("DexFile: survives pseudo-random inputs (ASan-checked)") {
  uint32_t seed = 0x12345678u;
  auto rnd = [&]() {
    seed = seed * 1103515245u + 12345u;
    return seed;
  };
  for (int iter = 0; iter < 3000; ++iter) {
    size_t n = 0x70 + (rnd() % 512);
    std::vector<uint8_t> b(n);
    for (size_t i = 0; i < n; ++i) b[i] = static_cast<uint8_t>(rnd() >> 16);
    StampHeader(b);
    DriveDex(b);
  }
  CHECK(true);
}

// Build a minimal, valid, empty DEX (zero classes) stamped with the given
// 3-character version and report whether DexFile::Init accepts it.
static bool InitEmptyDex(const char* ver) {
  std::vector<uint8_t> b(0x70, 0);
  static const uint8_t prefix[4] = {0x64, 0x65, 0x78, 0x0a};  // "dex\n"
  memcpy(b.data(), prefix, 4);
  b[4] = static_cast<uint8_t>(ver[0]);
  b[5] = static_cast<uint8_t>(ver[1]);
  b[6] = static_cast<uint8_t>(ver[2]);
  b[7] = 0x00;
  Put32(b, 32, static_cast<uint32_t>(b.size()));  // file_size
  Put32(b, 36, 0x70);                             // header_size
  Put32(b, 40, 0x12345678);                       // endian_tag

  aav::ObjPtr<IMemTarget> target = aav::MakeMemtarget();
  if (!target) return false;
  MemSource src;
  src.mode = O_RDONLY;
  src.name = "t.dex";
  src.buf = b.data();
  src.buf_size = static_cast<int>(b.size());
  if (0 != target->Init(&src)) return false;
  DexFile df;
  return 0 == df.Init(target.get());
}

TEST_CASE("DexFile: accepts DEX magic versions 035..040, rejects others") {
  CHECK(InitEmptyDex("035"));
  CHECK(InitEmptyDex("036"));
  CHECK(InitEmptyDex("037"));
  CHECK(InitEmptyDex("038"));
  CHECK(InitEmptyDex("039"));
  CHECK(InitEmptyDex("040"));
  CHECK_FALSE(InitEmptyDex("034"));
  CHECK_FALSE(InitEmptyDex("041"));
  CHECK_FALSE(InitEmptyDex("999"));
  CHECK_FALSE(InitEmptyDex("abc"));
}

TEST_CASE("DexCode: modern (DEX 038/039) opcodes walk with correct sizes") {
  // One of each method-handle / invoke-custom opcode at its real fixed length.
  // The removed jumbo table treated 0xff as a 2-byte expanded-opcode prefix and
  // would mis-walk this stream (wrong sizes -> wrong or failed fingerprint).
  std::vector<uint8_t> code;
  auto emit = [&](uint8_t op, int len) {
    code.push_back(op);
    for (int i = 1; i < len; ++i) code.push_back(0x00);
  };
  emit(0xfa, 8);  // invoke-polymorphic
  emit(0xfb, 8);  // invoke-polymorphic/range
  emit(0xfc, 6);  // invoke-custom
  emit(0xfd, 6);  // invoke-custom/range
  emit(0xfe, 4);  // const-method-handle
  emit(0xff, 4);  // const-method-type
  emit(0xfe, 4);
  emit(0xff, 4);

  DexFile df;  // unused by this code (no const-string), just a non-null ptr
  DexCode dc;
  REQUIRE(0 == dc.Init(&df, code.data(), code.data() + code.size()));

  FastOpcodes fo;
  REQUIRE(0 == dc.GetFastOpcodes(fo));
  CHECK(fo.opcode01 == 0xfbfa);  // {fa, fb}
  CHECK(fo.opcode23 == 0xfdfc);  // {fc, fd}
  CHECK(fo.opcode45 == 0xfffe);  // {fe, ff}
  CHECK(fo.opcode67 == 0xfffe);  // {fe, ff}

  CHECK(0 == dc.ParseCode());  // walks to the end cleanly (no -2 misalignment)
}

TEST_CASE("DexCode: fill-array-data payload is not walked as instructions") {
  // packed/sparse-switch and fill-array-data embed a data payload inside the
  // method body. ParseCode must clamp its walk to the earliest payload so the
  // payload bytes are never decoded as opcodes (which would corrupt the
  // fingerprint). Here the payload sits right after a fill-array-data whose
  // branch offset points at it.
  auto u16 = [](std::vector<uint8_t>& b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v & 0xff));
    b.push_back(static_cast<uint8_t>(v >> 8));
  };
  std::vector<uint8_t> code;
  u16(code, 0x0012);  // const/4 v0, #0
  u16(code, 0x0026);  // fill-array-data v0, +BBBBBBBB
  u16(code,
      0x0003);  //   branch offset low  (3 code units from here -> payload)
  u16(code, 0x0000);  //   branch offset high
  u16(code, 0x0300);  // payload: ident (0x0300)
  u16(code, 0x0001);  //   element_width = 1
  u16(code, 0x0001);  //   size low
  u16(code, 0x0000);  //   size high
  u16(code, 0x0000);  //   1 byte of data (padded to a code unit)

  DexFile df;
  DexCode dc;
  REQUIRE(0 == dc.Init(&df, code.data(), code.data() + code.size()));
  CHECK(0 == dc.ParseCode());

  // Only the two real instructions (const/4, fill-array-data) are
  // fingerprinted; the payload bytes are excluded because code_end_ was clamped
  // to the payload.
  uint32_t crc = 0;
  REQUIRE(0 == dc.GetOpcodeCrC32(crc));
  const uint8_t expected[] = {0x12, 0x26};
  CHECK(crc == aav::Crc32(0, expected, sizeof(expected)));
}
