//
// Blowfish C++ implementation
//
//

#ifndef AAV_UTILS_BLOWFISH_H_
#define AAV_UTILS_BLOWFISH_H_

#include <stdint.h>

#include <cstddef>
#include <string>

namespace aav {

class Blowfish {
 public:
  void SetKey(const std::string& key);
  void SetKey(const char* key, size_t byte_length);

  // Buffer will be padded with PKCS #5 automatically
  // "dst" and "src" must be different instance
  void Encrypt(std::string* dst, const std::string& src) const;
  void Decrypt(std::string* dst, const std::string& src) const;

  // Buffer length must be a multiple of the block length (64bit)
  void Encrypt(char* dst, const char* src, size_t byte_length) const;
  void Decrypt(char* dst, const char* src, size_t byte_length) const;

 private:
  void EncryptBlock(uint32_t* left, uint32_t* right) const;
  void DecryptBlock(uint32_t* left, uint32_t* right) const;
  uint32_t Feistel(uint32_t value) const;

 private:
  uint32_t pary_[18];
  uint32_t sbox_[4][256];
};

}  // namespace aav

#endif /* defined(AAV_UTILS_BLOWFISH_H_) */
