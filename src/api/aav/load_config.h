#ifndef AAV_LOAD_CONFIG_H_
#define AAV_LOAD_CONFIG_H_

#include <stdint.h>

namespace aav {

struct LoadModuleConfig {
  uint8_t unarch;
  uint8_t unpack;
  uint8_t apk;
  uint8_t dex;
  uint8_t elf;
  uint8_t oat;
  uint8_t reserve[2];  // padding
};

struct LoadFormatConfig {
  uint8_t ad;
  uint8_t apk;
  uint8_t dex;
  uint8_t elf;
  uint8_t oat;
  uint8_t white;
  uint8_t heur;
  uint8_t analyzer;
};

}  // namespace aav

#endif
