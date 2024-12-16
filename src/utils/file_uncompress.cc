#include "file_uncompress.h"

#include <zlib.h>

#include <cstring>
#include <string>

#include "crc32.h"

namespace aav {

// CRC-32 (zlib / ISO-HDLC) over a byte buffer, used to verify the signature DB.
// Delegates to aav::Crc32 so the project has a single CRC-32 implementation;
// it is bit-for-bit identical to zlib's crc32(0, ...), which sigtool uses to
// stamp the DB header.
unsigned long Crc32Buffer(unsigned char* ptr, int buf_len) {
  return Crc32(0, ptr, static_cast<uint32_t>(buf_len));
}

// Inflate an in-memory gzip stream (RFC 1952). Returns false on any zlib error.
bool GzipInflate(const std::string& compressed_bytes,
                 std::string& uncompressed_bytes) {
  uncompressed_bytes.clear();
  if (compressed_bytes.empty()) return true;

  z_stream strm;
  memset(&strm, 0, sizeof(strm));
  strm.next_in =
      reinterpret_cast<Bytef*>(const_cast<char*>(compressed_bytes.data()));
  strm.avail_in = static_cast<uInt>(compressed_bytes.size());

  // 16 + MAX_WBITS selects gzip header/trailer decoding (vs. raw zlib).
  if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) return false;

  char out[16384];
  int ret;
  do {
    strm.next_out = reinterpret_cast<Bytef*>(out);
    strm.avail_out = sizeof(out);
    ret = inflate(&strm, Z_NO_FLUSH);
    if (ret != Z_OK && ret != Z_STREAM_END) {
      inflateEnd(&strm);
      uncompressed_bytes.clear();
      return false;
    }
    uncompressed_bytes.append(out, sizeof(out) - strm.avail_out);
  } while (ret != Z_STREAM_END);

  inflateEnd(&strm);
  return true;
}

}  // namespace aav
