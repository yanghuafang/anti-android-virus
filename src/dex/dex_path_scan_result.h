#ifndef AAV_DEX_DEX_PATH_SCAN_RESULT_H_
#define AAV_DEX_DEX_PATH_SCAN_RESULT_H_

#include <stdint.h>

#include "dex_sig.h"

namespace aav {

// Accumulates, for one matched class-path sig_id, how many times each logic
// type (AND/OR/XOR/NOT) matched during a scan. IsMalware() folds those tallies
// into a single verdict for the sig.
class DexPathScanResult {
 public:
  DexPathScanResult();
  ~DexPathScanResult();

  uint32_t SigId();
  int SetSigId(uint32_t sig_id);
  int AddLogicMatchType(LogicMatchType logic_match_type);
  bool IsMalware();

 private:
  uint32_t sig_id_;
  int and_match_count_;
  int or_match_count_;
  int xor_match_count_;
  int not_match_count_;
};

}  // namespace aav

#endif
