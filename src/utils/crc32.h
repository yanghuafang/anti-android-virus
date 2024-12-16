#ifndef AAV_UTILS_CRC32_H_
#define AAV_UTILS_CRC32_H_

#include <stdint.h>

namespace aav {
uint32_t Crc32(uint32_t crc, const void* buf, uint32_t size);
}  // namespace aav

#endif
