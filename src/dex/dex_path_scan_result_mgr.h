#ifndef AAV_DEX_DEX_PATH_SCAN_RESULT_MGR_H_
#define AAV_DEX_DEX_PATH_SCAN_RESULT_MGR_H_

#include <cstdint>
#include <list>
#include <vector>

#include "dex/dex_sig.h"

namespace aav {

struct DexPathSig;

class DexPathScanResult;

// Gathers class-path signature hits for one file, one DexPathScanResult per
// sig_id (AddSigHit tallies each hit's logic type), then returns the sig_ids
// whose combined path logic marks them malware (GetMalwareSigIds).
class DexPathScanResultMgr {
 public:
  DexPathScanResultMgr();
  ~DexPathScanResultMgr();

  // Per-scan accumulator, filled through a reference and read once.
  DexPathScanResultMgr(const DexPathScanResultMgr&) = delete;
  DexPathScanResultMgr& operator=(const DexPathScanResultMgr&) = delete;

  int AddSigHit(const DexPathSig* path_sig);
  int GetMalwareSigIds(std::vector<uint32_t>& sig_id_array);

 private:
  std::list<DexPathScanResult> scan_result_list_;
};

}  // namespace aav

#endif
