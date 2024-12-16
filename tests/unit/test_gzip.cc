#include <zlib.h>

#include <cstring>
#include <string>

#include "crc32.h"
#include "doctest.h"
#include "file_uncompress.h"

using namespace aav;

// Produce a gzip stream (RFC 1952) so GzipInflate has real input to decode.
static std::string GzipDeflate(const std::string& in) {
  z_stream s;
  memset(&s, 0, sizeof(s));
  deflateInit2(&s, Z_BEST_COMPRESSION, Z_DEFLATED, 16 + MAX_WBITS, 8,
               Z_DEFAULT_STRATEGY);
  s.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
  s.avail_in = static_cast<uInt>(in.size());
  std::string out;
  char buf[4096];
  int ret;
  do {
    s.next_out = reinterpret_cast<Bytef*>(buf);
    s.avail_out = sizeof(buf);
    ret = deflate(&s, Z_FINISH);
    out.append(buf, sizeof(buf) - s.avail_out);
  } while (ret != Z_STREAM_END);
  deflateEnd(&s);
  return out;
}

TEST_CASE("GzipInflate round-trips gzip data") {
  std::string msg = "hello aav -- gzip round-trip payload. ";
  for (int i = 0; i < 6; ++i) msg += msg;  // grow so it actually compresses
  std::string out;
  CHECK(GzipInflate(GzipDeflate(msg), out));
  CHECK(out == msg);
}

TEST_CASE("GzipInflate returns empty for empty input") {
  std::string out = "sentinel";
  CHECK(GzipInflate("", out));
  CHECK(out.empty());
}

TEST_CASE("GzipInflate rejects non-gzip input") {
  std::string out;
  CHECK_FALSE(GzipInflate("this is not a gzip stream at all", out));
}

TEST_CASE("Crc32Buffer is the standard CRC-32 (== aav::Crc32)") {
  unsigned char data[] = "123456789";
  CHECK(Crc32Buffer(data, 9) == 0xCBF43926u);
  CHECK(Crc32Buffer(data, 9) == Crc32(0, data, 9));
}
