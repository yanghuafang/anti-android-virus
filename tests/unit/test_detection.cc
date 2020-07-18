// White-box tests for the DEX detection core, driven by a mock ISigMgr that
// serves hand-built signature sections. This exercises the (untrusted-input-
// hardened) section parsers, the binary-search lookups, and every branch of the
// code boolean logic -- without needing a real on-disk DB.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "aav/sig_format.h"  // SigItem, SigFormat
#include "aav/sig_mgr_interface.h"
#include "dex/dex_code_scan_result.h"
#include "dex/dex_code_scan_result_mgr.h"
#include "dex/dex_code_sig_mgr.h"  // DexCodeCrcSig, DexCodeLogicSig, FastOpcodes
#include "dex/dex_path_scan_result_mgr.h"
#include "dex/dex_path_sig_mgr.h"  // DexPathSig
#include "dex/dex_sig.h"           // match types, kBitMapSize
#include "dex/dex_sig_mgr.h"
#include "doctest.h"
#include "sig/common_define.h"  // kAdSuccess / kAdError
#include "utils/crc32.h"

using aav::Crc32;
using aav::DexCodeCrcSig;
using aav::DexCodeLogicSig;
using aav::DexCodeScanResult;
using aav::DexCodeScanResultMgr;
using aav::DexPathScanResultMgr;
using aav::DexPathSig;
using aav::DexSigMgr;
using aav::FastOpcodes;
using aav::ISigMgr;
using aav::kAdError;
using aav::kAdSuccess;
using aav::kBitMapSize;
using aav::kLogicMatchTypeAnd;
using aav::kLogicMatchTypeOr;
using aav::kSigFormatDexCodeLogic;
using aav::kSigFormatDexOpcodeCrc;
using aav::kSigFormatDexOpcodeMap;
using aav::kSigFormatDexOperandCrc;
using aav::kSigFormatDexPath;
using aav::kStrMatchTypeEqual;
using aav::LoadFormatConfig;
using aav::SigFormat;
using aav::SigItem;
using Bytes = std::vector<uint8_t>;

namespace {

void Put8(Bytes& b, uint8_t v) { b.push_back(v); }
void Put16(Bytes& b, uint16_t v) {
  b.push_back(v & 0xff);
  b.push_back((v >> 8) & 0xff);
}
void Put32(Bytes& b, uint32_t v) {
  for (int i = 0; i < 4; ++i) {
    b.push_back((v >> (8 * i)) & 0xff);
  }
}
uint32_t SegCrc(const char* s) {
  return Crc32(0, s, static_cast<uint32_t>(std::strlen(s)));
}

// A minimal ISigMgr that returns caller-supplied sections. Stack-allocated;
// DexSigMgr does not take ownership, so Destroy() is never called on it.
class MockSigMgr : public ISigMgr {
 public:
  void Add(SigFormat format, uint32_t sig_count, Bytes data) {
    bufs_.push_back(std::move(data));  // moving a vector keeps its data pointer
    SigItem it{};
    it.format = format;
    it.sig_count = sig_count;
    it.buf = bufs_.back().data();
    it.buf_size = static_cast<uint32_t>(bufs_.back().size());
    items_.push_back(it);
  }

  // Drop a section so a test can substitute a malformed one for it.
  void Clear(SigFormat format) {
    for (size_t i = 0; i < items_.size(); ++i) {
      if (items_[i].format == static_cast<uint32_t>(format)) {
        items_.erase(items_.begin() + static_cast<std::ptrdiff_t>(i));
        return;
      }
    }
  }

  int GetData(SigFormat format, SigItem** item) override {
    for (SigItem& it : items_) {
      if (it.format == static_cast<uint32_t>(format)) {
        *item = &it;
        return kAdSuccess;
      }
    }
    return kAdError;
  }

  int Init(void* /*context*/) override { return 0; }
  int Uninit() override { return 0; }
  int LoadSigs(const char* /*path*/,
               const LoadFormatConfig* /*config*/) override {
    return 0;
  }
  int UnloadSigs() override { return 0; }
  int UpdateSigs(const char* /*dir*/) override { return 0; }
  int SigVersion() override { return 1; }
  int GetMalwareName(int /*sig_id*/, char* /*name_buf*/,
                     int /*name_buf_size*/) override {
    return kAdError;
  }
  int GetAdInfo(int /*sig_id*/, void** /*ad_info*/) override {
    return kAdError;
  }

 private:
  std::vector<Bytes> bufs_;
  std::vector<SigItem> items_;
};

// Fast-opcode keys and standalone CRCs used by the map/crc-search sections.
constexpr uint16_t kFast01 = 0x1111, kFast23 = 0x2222;
constexpr uint16_t kFast45 = 0x3333, kFast67 = 0x4444;
constexpr uint32_t kOpcodeCrc = 0x00000100, kOperandCrc = 0x00000200;

// CRC constants used by the boolean-logic sections.
constexpr uint32_t kCrcA = 0xA1, kCrcB = 0xB2, kCrcOr = 0xC3;
constexpr uint32_t kCrcX1 = 0xD4, kCrcX2 = 0xE5, kCrcN = 0xF6, kCrcN2 = 0x17;

// Fills `m` with a full, self-consistent set of DEX sections.
void PopulateMock(MockSigMgr& m) {
  {  // DEX_PATH: one EQUAL/OR sig over com.test.evil (sig 5001)
    Bytes p;
    Put32(p, 5001);
    Put8(p, static_cast<uint8_t>(kStrMatchTypeEqual));
    Put8(p, static_cast<uint8_t>(kLogicMatchTypeOr));
    const char* segs[] = {"com", "test", "evil"};
    Put16(p, 3);
    for (const char* s : segs) {
      Put32(p, SegCrc(s));
    }
    m.Add(kSigFormatDexPath, 1, p);
  }
  {  // DEX opcode bitmap (4 maps x 8192 bytes)
    const int map_bytes = kBitMapSize / 8;
    Bytes maps(map_bytes * 4, 0);
    auto set = [&](int idx, uint16_t v) {
      maps[(idx * map_bytes) + (v >> 3)] |= static_cast<uint8_t>(1u << (v & 7));
    };
    set(0, kFast01);
    set(1, kFast23);
    set(2, kFast45);
    set(3, kFast67);
    m.Add(kSigFormatDexOpcodeMap, 4, maps);
  }
  {  // opcode-crc -> sig 2002
    Bytes c;
    Put32(c, kOpcodeCrc);
    Put32(c, 1);
    Put32(c, 2002);
    m.Add(kSigFormatDexOpcodeCrc, 1, c);
  }
  {  // operand-crc -> sig 2002
    Bytes c;
    Put32(c, kOperandCrc);
    Put32(c, 1);
    Put32(c, 2002);
    m.Add(kSigFormatDexOperandCrc, 1, c);
  }
  {  // code logic (sorted by sig_id for SearchCodeLogic's binary search)
    Bytes l;
    auto block = [&](std::initializer_list<uint32_t> crcs) {
      Put32(l, static_cast<uint32_t>(crcs.size()));
      for (uint32_t c : crcs) {
        Put32(l, c);
      }
    };
    auto sig = [&](uint32_t id, std::initializer_list<uint32_t> nots,
                   std::initializer_list<uint32_t> xors,
                   std::initializer_list<uint32_t> ands,
                   std::initializer_list<uint32_t> ors) {
      Put32(l, id);
      block(nots);
      block(xors);
      block(ands);
      block(ors);
    };
    sig(2002, {}, {}, {kCrcA, kCrcB}, {});    // AND
    sig(3001, {}, {}, {}, {kCrcOr});          // OR
    sig(3002, {}, {kCrcX1, kCrcX2}, {}, {});  // XOR (both present => veto)
    sig(3003, {kCrcN}, {}, {}, {});           // NOT (present => veto)
    sig(3005, {kCrcN2}, {}, {kCrcA, kCrcB},
        {});  // NOT absent + AND present => malware
    sig(3006, {}, {}, {kCrcA, kCrcB},
        {});  // AND with only one crc hit => no match
    m.Add(kSigFormatDexCodeLogic, 6, l);
  }
}

}  // namespace

TEST_CASE("DexSigMgr: class-path search via the Aho-Corasick trie") {
  MockSigMgr m;
  PopulateMock(m);
  DexSigMgr sm;
  REQUIRE(sm.Init(&m) == 0);

  DexPathSig* ps = nullptr;
  CHECK(sm.SearchClassPath("com.test.evil", &ps) == 0);
  REQUIRE(ps != nullptr);
  CHECK(ps->sig_id == 5001u);
  CHECK(sm.SearchClassPath("com.other.thing", &ps) != 0);
}

// A DEX_PATH record declares its own CRC count, so the section's length fields
// cannot be trusted to describe the section. Each case here overran the buffer
// or walked the cursor backwards before ParsePathSig bounds-checked its reads;
// Init must reject the section rather than parse past it.
TEST_CASE(
    "DexSigMgr: malformed DEX_PATH sections are rejected, not read past") {
  auto path_section = [](uint16_t declared_layers, int actual_crcs,
                         size_t truncate_to) {
    Bytes p;
    Put32(p, 5001);
    Put8(p, static_cast<uint8_t>(kStrMatchTypeEqual));
    Put8(p, static_cast<uint8_t>(kLogicMatchTypeOr));
    Put16(p, declared_layers);
    for (int i = 0; i < actual_crcs; ++i) {
      Put32(p, SegCrc("com"));
    }
    if (truncate_to < p.size()) {
      p.resize(truncate_to);
    }
    return p;
  };

  SUBCASE("declared layer count overruns the section") {
    MockSigMgr m;
    PopulateMock(m);
    m.Clear(kSigFormatDexPath);
    m.Add(kSigFormatDexPath, 1, path_section(0xffff, 1, 12));
    DexSigMgr sm;
    CHECK(sm.Init(&m) != 0);
  }
  SUBCASE("zero layers, which used to wrap the cursor advance") {
    MockSigMgr m;
    PopulateMock(m);
    m.Clear(kSigFormatDexPath);
    m.Add(kSigFormatDexPath, 1, path_section(0, 1, 12));
    DexSigMgr sm;
    CHECK(sm.Init(&m) != 0);
  }
  SUBCASE("record header truncated mid-field") {
    MockSigMgr m;
    PopulateMock(m);
    m.Clear(kSigFormatDexPath);
    m.Add(kSigFormatDexPath, 1, path_section(1, 1, 6));
    DexSigMgr sm;
    CHECK(sm.Init(&m) != 0);
  }
  SUBCASE("a well-formed section still loads") {
    MockSigMgr m;
    PopulateMock(m);
    DexSigMgr sm;
    CHECK(sm.Init(&m) == 0);
  }
}

TEST_CASE("DexSigMgr: opcode map + CRC lookups") {
  MockSigMgr m;
  PopulateMock(m);
  DexSigMgr sm;
  REQUIRE(sm.Init(&m) == 0);

  FastOpcodes hit{kFast01, kFast23, kFast45, kFast67};
  CHECK(sm.SearchOpcodeMap(&hit) == 0);
  FastOpcodes miss{0x1, 0x2, 0x3, 0x4};
  CHECK(sm.SearchOpcodeMap(&miss) != 0);

  DexCodeCrcSig* cs = nullptr;
  CHECK(sm.SearchOpcodeCrc(kOpcodeCrc, &cs) == 0);
  REQUIRE(cs != nullptr);
  CHECK(cs->crc == kOpcodeCrc);
  CHECK(sm.SearchOpcodeCrc(0x9999, &cs) != 0);
  CHECK(sm.SearchOperandCrc(kOperandCrc, &cs) == 0);

  DexCodeLogicSig* ls = nullptr;
  CHECK(sm.SearchCodeLogic(2002, &ls) == 0);
  REQUIRE(ls != nullptr);
  CHECK(ls->and_crcs.size() == 2);
  CHECK(sm.SearchCodeLogic(9999, &ls) != 0);
}

TEST_CASE("DexCodeScanResult stores a CRC set") {
  DexCodeScanResult r;
  r.SetSigId(2002);
  r.AddCrc(kCrcA);
  r.AddCrc(kCrcB);
  CHECK(r.SigId() == 2002u);
  CHECK(r.HasCrc(kCrcA));
  CHECK(r.HasCrc(kCrcB));
  CHECK_FALSE(r.HasCrc(0xDEAD));
}

TEST_CASE("DexCodeScanResultMgr evaluates AND/OR/XOR/NOT logic") {
  MockSigMgr m;
  PopulateMock(m);
  DexSigMgr sm;
  REQUIRE(sm.Init(&m) == 0);

  DexCodeScanResultMgr mgr;
  auto hit = [&](uint32_t crc, uint32_t sig_id) {
    DexCodeCrcSig c;
    c.crc = crc;
    c.sig_ids.push_back(sig_id);
    CHECK(mgr.AddSigHit(&c) == 0);
  };
  hit(kCrcA, 2002);
  hit(kCrcB, 2002);   // AND satisfied
  hit(kCrcOr, 3001);  // OR satisfied
  hit(kCrcX1, 3002);
  hit(kCrcX2, 3002);  // XOR both present => veto
  hit(kCrcN, 3003);   // NOT present => veto
  hit(kCrcA, 3005);
  hit(kCrcB, 3005);  // NOT(kCrcN2) absent + AND present => malware
  hit(kCrcA, 3006);  // AND needs kCrcB too => no match

  std::vector<uint32_t> ids;
  CHECK(mgr.GetMalwareSigIds(&sm, ids) == 0);
  auto has = [&](uint32_t v) {
    return std::find(ids.begin(), ids.end(), v) != ids.end();
  };
  CHECK(has(2002));
  CHECK(has(3001));
  CHECK(has(3005));
  CHECK_FALSE(has(3002));
  CHECK_FALSE(has(3003));
  CHECK_FALSE(has(3006));
}

TEST_CASE("DexPathScanResultMgr aggregates path hits into verdicts") {
  DexPathScanResultMgr pm;
  DexPathSig a{};
  a.sig_id = 7001;
  a.logic_match_type = kLogicMatchTypeOr;  // single OR => malware
  CHECK(pm.AddSigHit(&a) == 0);
  DexPathSig b{};
  b.sig_id = 7002;
  b.logic_match_type = kLogicMatchTypeAnd;  // single AND => not yet malware
  CHECK(pm.AddSigHit(&b) == 0);

  std::vector<uint32_t> ids;
  CHECK(pm.GetMalwareSigIds(ids) == 0);
  auto has = [&](uint32_t v) {
    return std::find(ids.begin(), ids.end(), v) != ids.end();
  };
  CHECK(has(7001));
  CHECK_FALSE(has(7002));
}
