#ifndef AAV_SCAN_RESULT_H_
#define AAV_SCAN_RESULT_H_

#include <stdint.h>
#include <stdlib.h>

#include <memory>

namespace aav {

struct ScanResult {
  uint8_t is_white;
  uint8_t is_malware;
  uint16_t scanner_id;
  uint16_t file_type;
  uint16_t sig_count;
  uint32_t sig_id[1];
};

// SCAN_RESULT is a variable-length structure built with malloc(); own it with a
// unique_ptr whose deleter free()s (rather than delete)s it.
struct ScanResultFree {
  void operator()(ScanResult* p) const { free(p); }
};
using ScanResultPtr = std::unique_ptr<ScanResult, ScanResultFree>;

}  // namespace aav

#endif
