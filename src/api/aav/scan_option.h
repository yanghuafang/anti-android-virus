#ifndef AAV_SCAN_OPTION_H_
#define AAV_SCAN_OPTION_H_

#include <stdint.h>

#include "aav/load_config.h"

namespace aav {

struct ScanOption {
  LoadModuleConfig config;
  uint32_t max_file_size;
  uint32_t max_unarch_layer;
  uint8_t max_unpack_layer;
  uint8_t heur_level;
  uint8_t reserve[2];
};

}  // namespace aav

#endif
