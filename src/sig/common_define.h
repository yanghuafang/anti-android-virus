#ifndef AAV_SIG_COMMON_DEFINE_H_
#define AAV_SIG_COMMON_DEFINE_H_

namespace aav {

constexpr int kFileNameLen = 256;

// error number
constexpr int kAdSuccess = 0;
constexpr int kAdError = 1;
constexpr int kAdSigLowVersion = 2;
constexpr int kAdSigCrc = 3;
constexpr int kAdSigLoad = 4;
constexpr int kAdSigEncrypt = 5;
constexpr int kAdSigUncompress = 6;
constexpr int kAdSigMagic = 7;

}  // namespace aav

#endif
