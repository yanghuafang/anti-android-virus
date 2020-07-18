#include "dex/dex_code_scan_result.h"

#include <cassert>
#include <new>

#include "utils/log.h"

namespace aav {

DexCodeScanResult::DexCodeScanResult() : sig_id_(0) {}

uint32_t DexCodeScanResult::SigId() const { return sig_id_; }

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
  return it != crc_set_.end();
}

}  // namespace aav
