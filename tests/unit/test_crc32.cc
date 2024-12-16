#include <cstdint>

#include "crc32.h"
#include "doctest.h"

// The engine's CRC32 must be the standard (reflected, IEEE) CRC-32 so that
// signature CRCs computed by sigtool match those computed by the scanner.
TEST_CASE("crc32 known vectors") {
  CHECK(aav::Crc32(0, "", 0) == 0u);
  CHECK(aav::Crc32(0, "123456789", 9) == 0xCBF43926u);
  CHECK(aav::Crc32(0, "a", 1) == 0xE8B7BE43u);
}
