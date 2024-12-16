#include "leb128.h"

#include <assert.h>

namespace aav {

// Signed LEB128. After reading N 7-bit groups the value occupies 7*N bits; the
// `(v << k) >> k` idiom sign-extends bit (7*N - 1) across the top by pushing
// the sign bit up to bit 31 and back down arithmetically (k = 32 - 7*N: 25, 18,
// 11, 4). Needing a 6th byte would overflow int32 -> error.
int ReadSleb128(const uint8_t* buf, int32_t* value, int* bytes_read) {
  int ret = 0;
  const uint8_t* p = buf;
  int32_t v = *(p++);
  if (v <= 0x7f)
    v = (v << 25) >> 25;  // expand the sign bit
  else {
    int cur = *(p++);
    v = (v & 0x7f) | ((cur & 0x7f) << 7);
    if (cur <= 0x7f)
      v = (v << 18) >> 18;
    else {
      cur = *(p++);
      v |= (cur & 0x7f) << 14;
      if (cur <= 0x7f)
        v = (v << 11) >> 11;
      else {
        cur = *(p++);
        v |= (cur & 0x7f) << 21;
        if (cur <= 0x7f)
          v |= (v << 4) >> 4;
        else {
          cur = *(p++);
          v |= (cur & 0x7f) << 28;
          if (cur > 0x7f) ret = -1;  // 6th byte needed -> overlong / overflow
        }
      }
    }
  }
  *value = v;
  *bytes_read = p - buf;
  return ret;
}

int ReadUleb128(const uint8_t* buf, uint32_t* value, int* bytes_read) {
  int ret = 0;
  const uint8_t* p = buf;
  uint32_t v = *(p++);
  if (v > 0x7f) {
    int cur = *(p++);
    v = (v & 0x7f) | ((cur & 0x7f) << 7);
    if (cur > 0x7f) {
      cur = *(p++);
      v |= (cur & 0x7f) << 14;
      if (cur > 0x7f) {
        cur = *(p++);
        v |= (cur & 0x7f) << 21;
        if (cur > 0x7f) {
          cur = *(p++);
          v |= (cur & 0x7f) << 28;
          if (cur > 0x7f) {
            ret = -1;
            // assert(false);
          }
        }
      }
    }
  }
  *value = v;
  *bytes_read = p - buf;
  return ret;
}

int ReadUleb128p1(const uint8_t* buf, uint32_t* value, int* bytes_read) {
  int ret = ReadUleb128(buf, value, bytes_read);
  if (0 == ret) (*value)++;
  return ret;
}

int ReadUleb128Safe(const uint8_t* buf, const uint8_t* end, uint32_t* value,
                    int* bytes_read) {
  const uint8_t* p = buf;
  uint32_t result = 0;
  int shift = 0;
  for (int i = 0; i < 5; ++i) {
    if (p >= end) return -1;
    uint8_t cur = *p++;
    result |= static_cast<uint32_t>(cur & 0x7f) << shift;
    if (0 == (cur & 0x80)) {
      *value = result;
      *bytes_read = static_cast<int>(p - buf);
      return 0;
    }
    shift += 7;
  }
  return -1;  // overlong encoding
}

}  // namespace aav
