#include "dex_code_scan_result.h"

#include <assert.h>

#include <new>

#include "log.h"

namespace aav {

DexCodeScanResult::DexCodeScanResult() { sig_id_ = 0; }

DexCodeScanResult::~DexCodeScanResult() {
  sig_id_ = 0;
  crc_set_.clear();
}

uint32_t DexCodeScanResult::SigId() { return sig_id_; }

int DexCodeScanResult::SetSigId(uint32_t sig_id) {
  assert(sig_id != 0);
  sig_id_ = sig_id;
  return 0;
}

int DexCodeScanResult::AddCrc(uint32_t crc) {
  try {
    crc_set_.insert(crc);
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexCodeScanResult::AddCrc bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

bool DexCodeScanResult::HasCrc(uint32_t crc) {
  std::set<uint32_t>::iterator it = crc_set_.find(crc);
  if (it != crc_set_.end()) return true;
  return false;
}

}  // namespace aav
