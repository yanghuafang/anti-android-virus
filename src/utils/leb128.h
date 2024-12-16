#ifndef AAV_UTILS_LEB128_H_
#define AAV_UTILS_LEB128_H_

#include <stdint.h>

namespace aav {

// LEB128 decoders (DEX uses little-endian base-128). ReadSleb128/ReadUleb128
// are UNCHECKED: the caller must guarantee at least 5 bytes are readable at
// `buf`. Prefer ReadUleb128Safe for untrusted input.
int ReadSleb128(const uint8_t* buf, int32_t* value, int* bytes_read);
int ReadUleb128(const uint8_t* buf, uint32_t* value, int* bytes_read);
// Bounded variant: never reads at or past `end`; returns -1 on truncation or
// an overlong (>5 byte) encoding.
int ReadUleb128Safe(const uint8_t* buf, const uint8_t* end, uint32_t* value,
                    int* bytes_read);
int ReadUleb128p1(const uint8_t* buf, uint32_t* value, int* bytes_read);

}  // namespace aav

#endif
