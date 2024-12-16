#include "dex_code_sig_mgr.h"

#include <assert.h>

#include <bitset>
#include <cstring>
#include <new>

#include "aav/sig_format.h"
#include "log.h"

namespace aav {

namespace {
// Read a uint32_t from a possibly-unaligned byte pointer. The signature DB is a
// packed byte stream; reading it through packed structs decays array members to
// naturally-aligned loads and trips UBSan, so use memcpy (alignment-safe).
inline uint32_t Rd32(const char* p) {
  uint32_t v;
  memcpy(&v, p, sizeof(v));
  return v;
}
}  // namespace

DexCodeSigMgr::DexCodeSigMgr() {}

DexCodeSigMgr::~DexCodeSigMgr() { Uninit(); }

int DexCodeSigMgr::Init(ISigMgr* sig_mgr) {
  if (nullptr == sig_mgr) return -1;

  SigItem* opcode_map = nullptr;
  SigItem* opcode_crc_sig = nullptr;
  SigItem* operand_crc_sig = nullptr;
  SigItem* code_logic_sig = nullptr;
  if (0 != sig_mgr->GetData(kSigFormatDexOpcodeMap, &opcode_map)) {
    AAV_LOGE("DexCodeSigMgr::Init GetData(kSigFormatDexOpcodeMap) failed");
    return -1;
  }
  if (0 != sig_mgr->GetData(kSigFormatDexOpcodeCrc, &opcode_crc_sig)) {
    AAV_LOGE("DexCodeSigMgr::Init GetData(kSigFormatDexOpcodeCrc) failed");
    return -1;
  }
  if (0 != sig_mgr->GetData(kSigFormatDexOperandCrc, &operand_crc_sig)) {
    AAV_LOGE("DexCodeSigMgr::Init GetData(kSigFormatDexOperandCrc) failed");
    return -1;
  }
  if (0 != sig_mgr->GetData(kSigFormatDexCodeLogic, &code_logic_sig)) {
    AAV_LOGE("DexCodeSigMgr::Init GetData(kSigFormatDexCodeLogic) failed");
    return -1;
  }
  if (0 != ParseOpcodeMap(opcode_map)) {
    AAV_LOGE("DexCodeSigMgr::Init ParseOpcodeMap failed");
    return -1;
  }
  if (0 != ParseOpcodeCrcSig(opcode_crc_sig)) {
    AAV_LOGE("DexCodeSigMgr::Init ParseOpcodeCrcSig failed");
    return -1;
  }
  if (0 != ParseOperandCrcSig(operand_crc_sig)) {
    AAV_LOGE("DexCodeSigMgr::Init ParseOperandCrcSig failed");
    return -1;
  }
  if (0 != ParseCodeLogicSig(code_logic_sig)) {
    AAV_LOGE("DexCodeSigMgr::Init ParseCodeLogicSig failed");
    return -1;
  }
  return 0;
}

int DexCodeSigMgr::Uninit() {
  opcode_map_.map01.reset();
  opcode_map_.map23.reset();
  opcode_map_.map45.reset();
  opcode_map_.map67.reset();

  opcode_crc_sig_array_.clear();
  operand_crc_sig_array_.clear();
  code_logic_sig_array_.clear();
  return 0;
}

// Bitmap pre-filter: a method can match a code signature only if each of its
// four opcode keys is set in the corresponding map. Any miss lets us skip the
// method before computing (more expensive) CRCs.
int DexCodeSigMgr::SearchOpcodeMap(const FastOpcodes* opcodes) {
  if (nullptr == opcodes) return -1;

  if (!opcode_map_.map01.test(opcodes->opcode01)) return -1;
  if (!opcode_map_.map23.test(opcodes->opcode23)) return -1;
  if (!opcode_map_.map45.test(opcodes->opcode45)) return -1;
  if (!opcode_map_.map67.test(opcodes->opcode67)) return -1;

  return 0;
}

int DexCodeSigMgr::SearchOpcodeCrc(uint32_t crc, DexCodeCrcSig** opcode_sig) {
  if (nullptr == opcode_sig) return -1;
  if (0 == opcode_crc_sig_array_.size()) return -1;

  int l = 0;
  int r = opcode_crc_sig_array_.size() - 1;
  while (l <= r) {
    int m = (l + r) / 2;
    int v = opcode_crc_sig_array_[m].crc;
    if (v < crc)
      l = m + 1;
    else if (v > crc)
      r = m - 1;
    else {
      *opcode_sig = &opcode_crc_sig_array_[m];
      return 0;
    }
  }
  return -1;
}

int DexCodeSigMgr::SearchOperandCrc(uint32_t crc, DexCodeCrcSig** operand_sig) {
  if (nullptr == operand_sig) return -1;
  if (0 == operand_crc_sig_array_.size()) return -1;

  int l = 0;
  int r = operand_crc_sig_array_.size() - 1;
  while (l <= r) {
    int m = (l + r) / 2;
    int v = operand_crc_sig_array_[m].crc;
    if (v < crc)
      l = m + 1;
    else if (v > crc)
      r = m - 1;
    else {
      *operand_sig = &operand_crc_sig_array_[m];
      return 0;
    }
  }
  return -1;
}

int DexCodeSigMgr::SearchCodeLogic(uint32_t sig_id,
                                   DexCodeLogicSig** logic_sig) {
  if (nullptr == logic_sig) return -1;
  if (0 == code_logic_sig_array_.size()) return -1;

  int l = 0;
  int r = code_logic_sig_array_.size() - 1;
  while (l <= r) {
    int m = (l + r) / 2;
    int v = code_logic_sig_array_[m].sig_id;
    if (v < sig_id)
      l = m + 1;
    else if (v > sig_id)
      r = m - 1;
    else {
      *logic_sig = &code_logic_sig_array_[m];
      return 0;
    }
  }
  return -1;
}

int DexCodeSigMgr::ParseOpcodeMap(const SigItem* opcode_map_item) {
  assert(nullptr != opcode_map_item);
  assert(kSigFormatDexOpcodeMap == opcode_map_item->format);
  assert((kFastOpcodesCount / 2) == opcode_map_item->sig_count);
  assert(nullptr != opcode_map_item->buf);
  assert(((kBitMapSize / 8) * (kFastOpcodesCount / 2)) ==
         opcode_map_item->buf_size);

  if (nullptr == opcode_map_item) return -1;
  if (kSigFormatDexOpcodeMap != opcode_map_item->format) return -1;
  if ((kFastOpcodesCount / 2) != opcode_map_item->sig_count) return -1;
  if (nullptr == opcode_map_item->buf) return -1;
  if (((kBitMapSize / 8) * (kFastOpcodesCount / 2)) !=
      opcode_map_item->buf_size)
    return -1;

  DexOpcodeMapRaw* opcode_map =
      static_cast<DexOpcodeMapRaw*>(opcode_map_item->buf);
  const uint8_t* map01 = opcode_map->map01;
  const uint8_t* map23 = opcode_map->map23;
  const uint8_t* map45 = opcode_map->map45;
  const uint8_t* map67 = opcode_map->map67;

  if (0 != PrepareOpcodeMap(map01, opcode_map_.map01)) return -1;
  if (0 != PrepareOpcodeMap(map23, opcode_map_.map23)) return -1;
  if (0 != PrepareOpcodeMap(map45, opcode_map_.map45)) return -1;
  if (0 != PrepareOpcodeMap(map67, opcode_map_.map67)) return -1;

  return 0;
}

int DexCodeSigMgr::ParseOpcodeCrcSig(const SigItem* opcode_crc_sig_item) {
  assert(nullptr != opcode_crc_sig_item);
  assert(kSigFormatDexOpcodeCrc == opcode_crc_sig_item->format);
  assert(nullptr != opcode_crc_sig_item->buf);

  if (nullptr == opcode_crc_sig_item) return -1;
  if (kSigFormatDexOpcodeCrc != opcode_crc_sig_item->format) return -1;
  if (0 == opcode_crc_sig_item->sig_count) {
    AAV_LOGE("DexCodeSigMgr::ParseOpcodeCrcSig: opcode crc sig count is zero");
    return -1;
  }
  if (nullptr == opcode_crc_sig_item->buf) return -1;
  if (0 == opcode_crc_sig_item->buf_size) {
    AAV_LOGE(
        "DexCodeSigMgr::ParseOpcodeCrcSig: opcode crc sig buffer is empty");
    return -1;
  }

  const char* buf_end = static_cast<const char*>(opcode_crc_sig_item->buf) +
                        opcode_crc_sig_item->buf_size;
  const char* cur = static_cast<const char*>(opcode_crc_sig_item->buf);
  try {
    opcode_crc_sig_array_.reserve(opcode_crc_sig_item->sig_count);
    for (uint32_t i = 0; i < opcode_crc_sig_item->sig_count; i++) {
      // DexCodeCrcSigRaw (packed):
      // [crc:u32][sig_id_count:u32][sig_ids:count*u32]
      if (buf_end - cur < static_cast<ptrdiff_t>(2 * sizeof(uint32_t)))
        return -1;
      DexCodeCrcSig opcode_sig;
      opcode_sig.crc = Rd32(cur);
      uint32_t id_count = Rd32(cur + sizeof(uint32_t));
      if (0 == id_count) return -1;
      cur += 2 * sizeof(uint32_t);
      if (static_cast<size_t>(buf_end - cur) / sizeof(uint32_t) < id_count)
        return -1;
      opcode_sig.sig_ids.reserve(id_count);
      for (uint32_t j = 0; j < id_count; j++, cur += sizeof(uint32_t))
        opcode_sig.sig_ids.push_back(Rd32(cur));
      opcode_crc_sig_array_.push_back(opcode_sig);
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexCodeSigMgr::ParseOpcodeCrcSig bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

int DexCodeSigMgr::ParseOperandCrcSig(const SigItem* operand_crc_sig_item) {
  assert(nullptr != operand_crc_sig_item);
  assert(kSigFormatDexOperandCrc == operand_crc_sig_item->format);
  assert(nullptr != operand_crc_sig_item->buf);

  if (nullptr == operand_crc_sig_item) return -1;
  if (kSigFormatDexOperandCrc != operand_crc_sig_item->format) return -1;
  if (0 == operand_crc_sig_item->sig_count) {
    AAV_LOGE(
        "DexCodeSigMgr::ParseOperandCrcSig: operand crc sig count is zero");
    return -1;
  }
  if (nullptr == operand_crc_sig_item->buf) return -1;
  if (0 == operand_crc_sig_item->buf_size) {
    AAV_LOGE(
        "DexCodeSigMgr::ParseOperandCrcSig: operand crc sig buffer is empty");
    return -1;
  }

  const char* buf_end = static_cast<const char*>(operand_crc_sig_item->buf) +
                        operand_crc_sig_item->buf_size;
  const char* cur = static_cast<const char*>(operand_crc_sig_item->buf);
  try {
    operand_crc_sig_array_.reserve(operand_crc_sig_item->sig_count);
    for (uint32_t i = 0; i < operand_crc_sig_item->sig_count; i++) {
      // DexCodeCrcSigRaw (packed):
      // [crc:u32][sig_id_count:u32][sig_ids:count*u32]
      if (buf_end - cur < static_cast<ptrdiff_t>(2 * sizeof(uint32_t)))
        return -1;
      DexCodeCrcSig operand_sig;
      operand_sig.crc = Rd32(cur);
      uint32_t id_count = Rd32(cur + sizeof(uint32_t));
      if (0 == id_count) return -1;
      cur += 2 * sizeof(uint32_t);
      if (static_cast<size_t>(buf_end - cur) / sizeof(uint32_t) < id_count)
        return -1;
      operand_sig.sig_ids.reserve(id_count);
      for (uint32_t j = 0; j < id_count; j++, cur += sizeof(uint32_t))
        operand_sig.sig_ids.push_back(Rd32(cur));
      operand_crc_sig_array_.push_back(operand_sig);
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexCodeSigMgr::ParseOperandCrcSig bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

int DexCodeSigMgr::ParseCodeLogicSig(const SigItem* code_logic_sig_item) {
  assert(nullptr != code_logic_sig_item);
  assert(kSigFormatDexCodeLogic == code_logic_sig_item->format);
  assert(nullptr != code_logic_sig_item->buf);

  if (nullptr == code_logic_sig_item) return -1;
  if (kSigFormatDexCodeLogic != code_logic_sig_item->format) return -1;
  if (0 == code_logic_sig_item->sig_count) {
    AAV_LOGE("DexCodeSigMgr::ParseCodeLogicSig: code logic sig count is zero");
    return -1;
  }
  if (nullptr == code_logic_sig_item->buf) return -1;
  if (0 == code_logic_sig_item->buf_size) {
    AAV_LOGE(
        "DexCodeSigMgr::ParseCodeLogicSig: code logic sig buffer is empty");
    return -1;
  }

  const char* buf_end = static_cast<const char*>(code_logic_sig_item->buf) +
                        code_logic_sig_item->buf_size;
  const char* cur = static_cast<const char*>(code_logic_sig_item->buf);

  // Reads a packed DexLogicCrcsRaw block ([crc_count:u32][crcs:count*u32]),
  // bounded by buf_end. Returns false on truncation.
  auto read_block = [&](std::vector<uint32_t>& out) -> bool {
    if (buf_end - cur < static_cast<ptrdiff_t>(sizeof(uint32_t))) return false;
    uint32_t count = Rd32(cur);
    cur += sizeof(uint32_t);
    if (static_cast<size_t>(buf_end - cur) / sizeof(uint32_t) < count)
      return false;
    out.reserve(count);
    for (uint32_t j = 0; j < count; j++, cur += sizeof(uint32_t))
      out.push_back(Rd32(cur));
    return true;
  };

  try {
    code_logic_sig_array_.reserve(code_logic_sig_item->sig_count);
    for (uint32_t i = 0; i < code_logic_sig_item->sig_count; i++) {
      DexCodeLogicSig logic_sig;
      if (buf_end - cur < static_cast<ptrdiff_t>(sizeof(uint32_t))) return -1;
      logic_sig.sig_id = Rd32(cur);  // sig_id
      cur += sizeof(uint32_t);

      // Blocks are ordered NOT, XOR, AND, OR.
      if (!read_block(logic_sig.not_crcs)) return -1;
      if (!read_block(logic_sig.xor_crcs)) return -1;
      if (!read_block(logic_sig.and_crcs)) return -1;
      if (!read_block(logic_sig.or_crcs)) return -1;

      code_logic_sig_array_.push_back(logic_sig);
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexCodeSigMgr::ParseCodeLogicSig bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

// Unpack one packed on-disk bitmap into a std::bitset for O(1) membership
// tests. The file stores kBitMapSize bits as little-endian 32-bit words, LSB
// first (bit b of word w -> position 32*w + b).
int DexCodeSigMgr::PrepareOpcodeMap(const uint8_t* map_in_file,
                                    std::bitset<kBitMapSize>& map_in_mem) {
  assert(nullptr != map_in_file);

  for (int i = 0; i < kBitMapSize / (8 * 4); i++) {
    uint32_t base = 8 * 4 * i;
    uint32_t value =
        Rd32(reinterpret_cast<const char*>(map_in_file) + i * sizeof(uint32_t));
    uint32_t mask = 0x01;
    for (int j = 0; j < 8 * 4; j++) {
      if (0 != (value & mask)) {
        int pos = base + j;
        map_in_mem.set(pos);
      }
      mask <<= 1;
    }
  }

  return 0;
}

}  // namespace aav
