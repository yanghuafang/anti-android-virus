#ifndef AAV_SIG_SIG_DB_STRUCTURE_H_
#define AAV_SIG_SIG_DB_STRUCTURE_H_

#include <stdint.h>

namespace aav {

// SigHeader::magic value: the ASCII bytes "AAV1" as they appear on disk
// ('A','A','V','1'). The signature DB is a little-endian format, so the bytes
// pack into this uint32_t in that order.
constexpr uint32_t kSigMagic =
    static_cast<uint32_t>('A') | (static_cast<uint32_t>('A') << 8) |
    (static_cast<uint32_t>('V') << 16) | (static_cast<uint32_t>('1') << 24);

#pragma pack(push, 1)

struct SigHeader {
  uint32_t magic;
  uint32_t version;
  uint32_t timestamp;
  uint32_t crc;
};

struct SigSectionHeader {
  uint32_t format;
  uint32_t sig_count;
  uint32_t packed_size;
  uint32_t unpacked_size;
};

struct SigSection {
  SigSectionHeader header;
  uint8_t data[1];
};

struct SigFile {
  SigHeader header;
  SigSection sections[1];
};

#pragma pack(pop)

}  // namespace aav

#endif
