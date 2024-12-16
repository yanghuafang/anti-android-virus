#include "dex_path_scan_result.h"

#include <assert.h>

namespace aav {

DexPathScanResult::DexPathScanResult() {
  sig_id_ = 0;
  and_match_count_ = 0;
  or_match_count_ = 0;
  xor_match_count_ = 0;
  not_match_count_ = 0;
}

DexPathScanResult::~DexPathScanResult() {}

uint32_t DexPathScanResult::SigId() { return sig_id_; }

int DexPathScanResult::SetSigId(uint32_t sig_id) {
  assert(sig_id != 0);
  sig_id_ = sig_id;
  return 0;
}

int DexPathScanResult::AddLogicMatchType(LogicMatchType logic_match_type) {
  int ret = 0;

  switch (logic_match_type) {
    case kLogicMatchTypeAnd:
      and_match_count_++;
      break;
    case kLogicMatchTypeOr:
      or_match_count_++;
      break;
    case kLogicMatchTypeXor:
      xor_match_count_++;
      break;
    case kLogicMatchTypeNot:
      not_match_count_++;
      break;
    default:
      assert(false);
      ret = -1;
      break;
  }

  return ret;
}

// Combine the per-logic-type match tallies for this sig_id into a verdict.
// Vetoes first: any NOT match, or more than one XOR match, clears the sig. Then
// affirmations: a single OR match suffices; AND needs at least two members to
// have matched; a lone XOR match counts. (These rules mirror the path-signature
// logic in the thesis this engine implements.)
bool DexPathScanResult::IsMalware() {
  if (not_match_count_ > 0) return false;
  if (xor_match_count_ > 1) return false;

  if (or_match_count_ > 0) return true;
  if (and_match_count_ > 1) return true;
  if (1 == xor_match_count_) return true;

  return false;
}

}  // namespace aav
