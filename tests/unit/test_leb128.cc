#include <cstdint>

#include "doctest.h"
#include "leb128.h"

using namespace aav;

static uint32_t Decode(const uint8_t* b, int expected_bytes) {
  uint32_t value = 0;
  int bytes_read = 0;
  CHECK(ReadUleb128(b, &value, &bytes_read) == 0);
  CHECK(bytes_read == expected_bytes);
  return value;
}

TEST_CASE("read_uleb128 decodes canonical values") {
  {
    uint8_t b[] = {0x00};
    CHECK(Decode(b, 1) == 0u);
  }
  {
    uint8_t b[] = {0x7f};
    CHECK(Decode(b, 1) == 127u);
  }
  {
    uint8_t b[] = {0x80, 0x01};
    CHECK(Decode(b, 2) == 128u);
  }
  {
    uint8_t b[] = {0xff, 0x7f};
    CHECK(Decode(b, 2) == 16383u);
  }
  {
    uint8_t b[] = {0x80, 0x80, 0x01};
    CHECK(Decode(b, 3) == 16384u);
  }
  {  // 5-byte value
    uint8_t b[] = {0x80, 0x80, 0x80, 0x80, 0x0f};
    CHECK(Decode(b, 5) == 0xf0000000u);
  }
}

TEST_CASE("read_uleb128 rejects an overlong 5th-byte continuation") {
  uint8_t b[] = {0xff, 0xff, 0xff, 0xff, 0xff};
  uint32_t value = 0;
  int bytes_read = 0;
  CHECK(ReadUleb128(b, &value, &bytes_read) == -1);
}

TEST_CASE("read_uleb128p1 decodes value + 1") {
  uint8_t b0[] = {0x00};
  uint32_t value = 0;
  int bytes_read = 0;
  CHECK(ReadUleb128p1(b0, &value, &bytes_read) == 0);
  CHECK(value == 1u);
  uint8_t b1[] = {0x7f};
  CHECK(ReadUleb128p1(b1, &value, &bytes_read) == 0);
  CHECK(value == 128u);
}

static int32_t DecodeS(const uint8_t* b, int expected_bytes) {
  int32_t value = 0;
  int bytes_read = 0;
  CHECK(ReadSleb128(b, &value, &bytes_read) == 0);
  CHECK(bytes_read == expected_bytes);
  return value;
}

TEST_CASE("read_sleb128 decodes signed values across byte widths") {
  {
    uint8_t b[] = {0x00};
    CHECK(DecodeS(b, 1) == 0);
  }
  {
    uint8_t b[] = {0x02};
    CHECK(DecodeS(b, 1) == 2);
  }
  {
    uint8_t b[] = {0x7e};
    CHECK(DecodeS(b, 1) == -2);
  }
  {
    uint8_t b[] = {0x40};
    CHECK(DecodeS(b, 1) == -64);
  }
  {
    uint8_t b[] = {0xff, 0x00};
    CHECK(DecodeS(b, 2) == 127);
  }
  {
    uint8_t b[] = {0x80, 0x7f};
    CHECK(DecodeS(b, 2) == -128);
  }
  {  // 3-byte
    uint8_t b[] = {0x80, 0x80, 0x01};
    CHECK(DecodeS(b, 3) == 0x4000);
  }
  {  // 4-byte (exercises the 4-byte sign-extension path)
    uint8_t b[] = {0x80, 0x80, 0x80, 0x01};
    CHECK(DecodeS(b, 4) == 0x200000);
  }
}

TEST_CASE("read_sleb128 rejects an overlong 5th-byte continuation") {
  uint8_t b[] = {0x80, 0x80, 0x80, 0x80, 0x80};
  int32_t value = 0;
  int bytes_read = 0;
  CHECK(ReadSleb128(b, &value, &bytes_read) == -1);
}
