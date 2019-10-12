#ifndef AAV_UTILS_FILE_UNCOMPRESS_H_
#define AAV_UTILS_FILE_UNCOMPRESS_H_

#include <cstdint>
#include <string>

namespace aav {

bool GzipInflate(const std::string& compressed_bytes,
                 std::string& uncompressed_bytes);
uint32_t Crc32Buffer(const uint8_t* ptr, int buf_len);

}  // namespace aav

#endif
