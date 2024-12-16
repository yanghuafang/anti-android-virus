#ifndef AAV_UTILS_FILE_UNCOMPRESS_H_
#define AAV_UTILS_FILE_UNCOMPRESS_H_

#include <string>

namespace aav {

bool GzipInflate(const std::string& compressed_bytes,
                 std::string& uncompressed_bytes);
unsigned long Crc32Buffer(unsigned char* ptr, int buf_len);

}  // namespace aav

#endif
