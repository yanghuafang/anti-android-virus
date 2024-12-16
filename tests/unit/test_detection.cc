// White-box tests for the DEX detection core, driven by a mock ISigMgr that
// serves hand-built signature sections. This exercises the (untrusted-input-
// hardened) section parsers, the binary-search lookups, and every branch of the
// code boolean logic -- without needing a real on-disk DB.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

#include "aav/sig_format.h"  // SigItem, SigFormat
#include "aav/sig_mgr_interface.h"
#include "common_define.h"  // kAdSuccess / kAdError
#include "crc32.h"
#include "dex_code_scan_result.h"
#include "dex_code_scan_result_mgr.h"
#include "dex_code_sig_mgr.h"  // DexCodeCrcSig, DexCodeLogicSig, FastOpcodes
#include "dex_path_scan_result_mgr.h"
#include "dex_path_sig_mgr.h"  // DexPathSig
#include "dex_sig.h"           // match types, kBitMapSize
#include "dex_sig_mgr.h"
#include "doctest.h"

using namespace aav;
using Bytes = std::vector<uint8_t>;

namespace {

void Put8(Bytes& b, uint8_t v) { b.push_back(v); }
void Put16(Bytes& b, uint16_t v) {
  b.push_back(v & 0xff);
  b.push_back((v >> 8) & 0xff);
}
void Put32(Bytes& b, uint32_t v) {
  for (int i = 0; i < 4; ++i) b.push_back((v >> (8 * i)) & 0xff);
}
uint32_t SegCrc(const char* s) {
  return Crc32(0, s, static_cast<uint32_t>(strlen(s)));
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

  int GetData(SigFormat format, SigItem** item) override {
    for (SigItem& it : items_) {
      if (it.format == static_cast<uint32_t>(format)) {
        *item = &it;
        return kAdSuccess;
      }
    }
    return kAdError;
  }

  int Init(void*) override { return 0; }
  int Uninit() override { return 0; }
  int LoadSigs(const char*, const LoadFormatConfig*) override { return 0; }
  int UnloadSigs() override { return 0; }
  int UpdateSigs(const char*) override { return 0; }
  int SigVersion() override { return 1; }
  int GetMalwareName(int, char*, int) override { return kAdError; }
  int GetAdInfo(int, void**) override { return kAdError; }

 private:
  std::vector<Bytes> bufs_;
  std::vector<SigItem> items_;
};

// Fast-opcode keys and standalone CRCs used by the map/crc-search sections.
constexpr uint16_t kFast01 = 0x1111, kFast23 = 0x2222;
constexpr uint16_t kFast45 = 0x3333, kFast67 = 0x4444;
constexpr uint32_t kOpcodeCrc = 0x00000100, kOperandCrc = 0x00000200;

// CRC constants used by the boolean-logic sections.
constexpr uint32_t cA = 0xA1, cB = 0xB2, cOr = 0xC3;
constexpr uint32_t cX1 = 0xD4, cX2 = 0xE5, cN = 0xF6, cN2 = 0x17;

// Fills `m` with a full, self-consistent set of DEX sections.
void PopulateMock(MockSigMgr& m) {
  {  // DEX_PATH: one EQUAL/OR sig over com.test.evil (sig 5001)
    Bytes p;
    Put32(p, 5001);
    Put8(p, static_cast<uint8_t>(kStrMatchTypeEqual));
    Put8(p, static_cast<uint8_t>(kLogicMatchTypeOr));
    const char* segs[] = {"com", "test", "evil"};
    Put16(p, 3);
    for (const char* s : segs) Put32(p, SegCrc(s));
    m.Add(kSigFormatDexPath, 1, p);
  }
  {  // DEX opcode bitmap (4 maps x 8192 bytes)
    const int map_bytes = kBitMapSize / 8;
    Bytes maps(map_bytes * 4, 0);
    auto set = [&](int idx, uint16_t v) {
      maps[idx * map_bytes + (v >> 3)] |= static_cast<uint8_t>(1u << (v & 7));
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
      for (uint32_t c : crcs) Put32(l, c);
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
    sig(2002, {}, {}, {cA, cB}, {});     // AND
    sig(3001, {}, {}, {}, {cOr});        // OR
    sig(3002, {}, {cX1, cX2}, {}, {});   // XOR (both present => veto)
    sig(3003, {cN}, {}, {}, {});         // NOT (present => veto)
    sig(3005, {cN2}, {}, {cA, cB}, {});  // NOT absent + AND present => malware
    sig(3006, {}, {}, {cA, cB}, {});  // AND with only one crc hit => no match
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
  r.AddCrc(cA);
  r.AddCrc(cB);
  CHECK(r.SigId() == 2002u);
  CHECK(r.HasCrc(cA));
  CHECK(r.HasCrc(cB));
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
  hit(cA, 2002);
  hit(cB, 2002);   // AND satisfied
  hit(cOr, 3001);  // OR satisfied
  hit(cX1, 3002);
  hit(cX2, 3002);  // XOR both present => veto
  hit(cN, 3003);   // NOT present => veto
  hit(cA, 3005);
  hit(cB, 3005);  // NOT(cN2) absent + AND present => malware
  hit(cA, 3006);  // AND needs cB too => no match

  std::vector<uint32_t> ids;
  CHECK(mgr.GetMalwareSigIDs(&sm, ids) == 0);
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
  CHECK(pm.GetMalwareSigIDs(ids) == 0);
  auto has = [&](uint32_t v) {
    return std::find(ids.begin(), ids.end(), v) != ids.end();
  };
  CHECK(has(7001));
  CHECK_FALSE(has(7002));
}
