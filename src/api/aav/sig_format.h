#ifndef AAV_SIG_FORMAT_H_
#define AAV_SIG_FORMAT_H_

#include <stdint.h>

namespace aav {

enum SigFormat {
  kSigFormatUnknown = 0,

  // Malware Name
  kSigFormatType = 10,
  kSigFormatFamily,
  kSigFormatVariant,
  kSigFormatPlatform,
  kSigFormatFileFormat,
  kSigFormatName,
  kSigFormatSig,

  // Ad info format
  kSigFormatAdInfo = 20,

  // DEX format
  kSigFormatDexPath = 30,
  kSigFormatDexOpcodeMap,
  kSigFormatDexOpcodeCrc,
  kSigFormatDexOperandCrc,
  kSigFormatDexCodeLogic,

  // ELF format
  kSigFormatElfArm = 40,
  kSigFormatElfArM64,
  kSigFormatElfX86,
  kSigFormatElfX8664,
  kSigFormatElfMips,
  kSigFormatElfMipS64,

  // OAT format
  kSigFormatOatArm = 50,
  kSigFormatOatArM64,
  kSigFormatOatX86,
  kSigFormatOatX8664,
  kSigFormatOatMips,
  kSigFormatOatMipS64,

  // Mach-O format
  kSigFormatMachoArm = 60,
  kSigFormatMachoArM64,
  kSigFormatMachoX86,
  kSigFormatMachoX8664,
  kSigFormatMachoMips,
  kSigFormatMachoMipS64,

  // PE format
  kSigFormatPeArm = 70,
  kSigFormatPeArM64,
  kSigFormatPeX86,
  kSigFormatPeX8664,
  kSigFormatPeMips,
  kSigFormatPeMipS64,

  // White format
  kSigFormatWhiteApk = 80,
  kSigFormatWhiteDex,
  kSigFormatWhiteElf,
  kSigFormatWhiteOat,
};

struct SigItem {
  uint32_t format;
  uint32_t sig_count;
  void* buf;
  uint32_t buf_size;
};

}  // namespace aav

#endif
