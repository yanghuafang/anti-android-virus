#ifndef AAV_DEX_DEX_CODE_SCAN_RESULT_H_
#define AAV_DEX_DEX_CODE_SCAN_RESULT_H_

#include <stdint.h>

#include <set>

#include "dex_sig.h"

namespace aav {

// The set of code CRCs seen in a file for one candidate sig_id. Its owner
// (DexCodeScanResultMgr) evaluates the sig's DEX_CODE_LOGIC expression against
// this set; a std::set gives dedup + membership tests for that evaluation.
class DexCodeScanResult {
 public:
  DexCodeScanResult();
  ~DexCodeScanResult();

  uint32_t SigId();
  int SetSigId(uint32_t sig_id);
  int AddCrc(uint32_t crc);
  bool HasCrc(uint32_t crc);

 private:
  uint32_t sig_id_;
  std::set<uint32_t> crc_set_;
};

}  // namespace aav

#endif
