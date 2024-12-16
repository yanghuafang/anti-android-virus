#include "dex_path_scan_result_mgr.h"

#include <stdio.h>

#include <new>

#include "dex_path_scan_result.h"
#include "dex_path_sig_mgr.h"
#include "log.h"

namespace aav {

DexPathScanResultMgr::DexPathScanResultMgr() {}

DexPathScanResultMgr::~DexPathScanResultMgr() { scan_result_list_.clear(); }

int DexPathScanResultMgr::AddSigHit(const DexPathSig* path_sig) {
  if (nullptr == path_sig) return -1;

  bool found = false;
  for (std::list<DexPathScanResult>::iterator i = scan_result_list_.begin();
       i != scan_result_list_.end(); ++i) {
    if (path_sig->sig_id == i->SigId()) {
      i->AddLogicMatchType(path_sig->logic_match_type);
      found = true;
      break;
    }
  }

  if (!found) {
    DexPathScanResult result;
    result.SetSigId(path_sig->sig_id);
    result.AddLogicMatchType(path_sig->logic_match_type);
    try {
      scan_result_list_.push_back(result);
    } catch (std::bad_alloc& e) {
      AAV_LOGE("DexPathScanResultMgr::AddSigHit bad_alloc: %s", e.what());
      return -1;
    }
  }
  return 0;
}

int DexPathScanResultMgr::GetMalwareSigIDs(
    std::vector<uint32_t>& sig_id_array) {
  try {
    for (std::list<DexPathScanResult>::iterator i = scan_result_list_.begin();
         i != scan_result_list_.end(); ++i) {
      if (i->IsMalware()) sig_id_array.push_back(i->SigId());
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexPathScanResultMgr::GetMalwareSigIDs bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

}  // namespace aav
