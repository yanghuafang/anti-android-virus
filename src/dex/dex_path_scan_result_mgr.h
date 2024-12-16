#ifndef AAV_DEX_DEX_PATH_SCAN_RESULT_MGR_H_
#define AAV_DEX_DEX_PATH_SCAN_RESULT_MGR_H_

#include <stdint.h>

#include <list>
#include <vector>

#include "dex_sig.h"

namespace aav {

struct DexPathSig;

class DexPathScanResult;

// Gathers class-path signature hits for one file, one DexPathScanResult per
// sig_id (AddSigHit tallies each hit's logic type), then returns the sig_ids
// whose combined path logic marks them malware (GetMalwareSigIDs).
class DexPathScanResultMgr {
 public:
  DexPathScanResultMgr();
  ~DexPathScanResultMgr();

  int AddSigHit(const DexPathSig* path_sig);
  int GetMalwareSigIDs(std::vector<uint32_t>& sig_id_array);

 private:
  std::list<DexPathScanResult> scan_result_list_;
};

}  // namespace aav

#endif
