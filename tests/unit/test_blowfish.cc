#include <string>

#include "blowfish.h"
#include "doctest.h"

using namespace aav;

TEST_CASE("Blowfish encrypt/decrypt round-trips (PKCS#5 padded)") {
  Blowfish bf;
  bf.SetKey(std::string("a-unit-test-key-0123456789"));
  const std::string cases[] = {"",
                               "x",
                               "the quick brown fox jumps",
                               std::string(64, '\xAB')};
  for (const std::string& msg : cases) {
    std::string enc;
    std::string dec;
    bf.Encrypt(&enc, msg);
    CHECK(enc.size() % 8 == 0);  // padded up to the 64-bit block size
    bf.Decrypt(&dec, enc);
    CHECK(dec == msg);
  }
}

TEST_CASE("Blowfish decrypt with the wrong key does not recover plaintext") {
  Blowfish a;
  Blowfish b;
  a.SetKey(std::string("key-one"));
  b.SetKey(std::string("key-two"));
  std::string enc;
  std::string dec;
  a.Encrypt(&enc, "a secret payload string");
  b.Decrypt(&dec, enc);
  CHECK(dec != "a secret payload string");
}

TEST_CASE("Blowfish empty key is guarded (no crash, self-consistent)") {
  Blowfish bf;
  bf.SetKey(std::string(""));  // guarded: cipher stays at its unkeyed state
  std::string enc;
  std::string dec;
  bf.Encrypt(&enc, "payload");
  bf.Decrypt(&dec, enc);
  CHECK(dec == "payload");
}

TEST_CASE("Blowfish char-buffer block API round-trips") {
  Blowfish bf;
  bf.SetKey(std::string("block-api-key"));
  char src[16];
  for (int i = 0; i < 16; ++i) src[i] = static_cast<char>(i * 3 + 1);
  char enc[16];
  char dec[16];
  bf.Encrypt(enc, src, sizeof(enc));
  bf.Decrypt(dec, enc, sizeof(dec));
  CHECK(std::string(dec, 16) == std::string(src, 16));
}
