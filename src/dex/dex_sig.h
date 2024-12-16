#ifndef AAV_DEX_DEX_SIG_H_
#define AAV_DEX_DEX_SIG_H_

#include <stdint.h>

#include <vector>

namespace aav {

constexpr int kBitMapSize = 65536;

enum StrMatchType {
  kStrMatchTypeUnknown = 0,
  kStrMatchTypeEqual,
  kStrMatchTypeStartWith,
  kStrMatchTypeEndWith,
  kStrMatchTypeContain,
  kStrMatchTypeEndUnknown,
};

enum LogicMatchType {
  kLogicMatchTypeUnknown = 0,
  kLogicMatchTypeAnd,
  kLogicMatchTypeOr,
  kLogicMatchTypeXor,
  kLogicMatchTypeNot,
  kLogicMatchTypeEndUnknown,
};

#pragma pack(push, 1)

struct DexPathSigRaw {
  uint32_t sig_id;
  uint8_t str_match_type;    // enum STR_MATCH_TYPE
  uint8_t logic_match_type;  // enum LOGIC_MATCH_TYPE
  uint16_t path_max_layer;   // count of CRC
  uint32_t path_crcs[1];
};

struct DexOpcodeMapRaw {
  uint8_t map01[kBitMapSize / 8];
  uint8_t map23[kBitMapSize / 8];
  uint8_t map45[kBitMapSize / 8];
  uint8_t map67[kBitMapSize / 8];
};

struct DexCodeCrcSigRaw {
  uint32_t crc;
  uint32_t sig_id_count;
  uint32_t sig_ids[1];
};

struct DexLogicCrcsRaw {
  uint32_t crc_count;
  uint32_t crcs[1];
};

struct DexCodeLogicSigRaw {
  uint32_t sig_id;
  struct DexLogicCrcsRaw not_crcs;
  struct DexLogicCrcsRaw xor_crcs;
  struct DexLogicCrcsRaw and_crcs;
  struct DexLogicCrcsRaw or_crcs;
};

#pragma pack(pop)

}  // namespace aav

#endif
