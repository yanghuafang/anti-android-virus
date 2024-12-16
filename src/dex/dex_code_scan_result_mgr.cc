#include "dex_code_scan_result_mgr.h"

#include <assert.h>
#include <stdio.h>

#include <new>

#include "dex_code_scan_result.h"
#include "dex_code_sig_mgr.h"
#include "dex_sig_mgr.h"
#include "log.h"

namespace aav {

DexCodeScanResultMgr::DexCodeScanResultMgr() {}

DexCodeScanResultMgr::~DexCodeScanResultMgr() { scan_result_list_.clear(); }

int DexCodeScanResultMgr::AddSigHit(DexCodeCrcSig* code_sig) {
  if (nullptr == code_sig) return -1;

  for (std::vector<uint32_t>::iterator i = code_sig->sig_ids.begin();
       i != code_sig->sig_ids.end(); ++i) {
    bool found = false;
    for (std::list<DexCodeScanResult>::iterator j = scan_result_list_.begin();
         j != scan_result_list_.end(); ++j) {
      if (j->SigId() == *i) {
        if (0 != j->AddCrc(code_sig->crc)) return -1;
        found = true;
        break;
      }
    }

    if (!found) {
      DexCodeScanResult result;
      result.SetSigId(*i);
      result.AddCrc(code_sig->crc);
      try {
        scan_result_list_.push_back(result);
      } catch (std::bad_alloc& e) {
        AAV_LOGE("DexCodeScanResultMgr::AddSigHit bad_alloc: %s", e.what());
        return -1;
      }
    }
  }
  return 0;
}

int DexCodeScanResultMgr::GetMalwareSigIDs(
    DexSigMgr* dex_sig_mgr, std::vector<uint32_t>& sig_id_array) {
  if (nullptr == dex_sig_mgr) return -1;

  // For each candidate sig_id, evaluate its DEX_CODE_LOGIC expression over the
  // CRCs collected for it. NOT and XOR are vetoes: if satisfied, the sig is
  // cleared (skip it). Otherwise AND or OR being satisfied confirms malware.
  try {
    for (std::list<DexCodeScanResult>::iterator i = scan_result_list_.begin();
         i != scan_result_list_.end(); ++i) {
      DexCodeLogicSig* logic_sig = nullptr;
      if (0 != dex_sig_mgr->SearchCodeLogic(i->SigId(), &logic_sig)) return -1;
      assert(i->SigId() == logic_sig->sig_id);

      if (!logic_sig->not_crcs.empty()) {
        if (MatchNotLogic(*logic_sig, *i)) continue;
      }
      if (!logic_sig->xor_crcs.empty()) {
        if (MatchXorLogic(*logic_sig, *i)) continue;
      }

      bool found_malware = false;
      if (!found_malware && !logic_sig->and_crcs.empty()) {
        if (MatchAndLogic(*logic_sig, *i)) found_malware = true;
      }
      if (!found_malware && !logic_sig->or_crcs.empty()) {
        if (MatchOrLogic(*logic_sig, *i)) found_malware = true;
      }
      if (found_malware) sig_id_array.push_back(i->SigId());
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexCodeScanResultMgr::GetMalwareSigIDs bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

bool DexCodeScanResultMgr::MatchNotLogic(DexCodeLogicSig& logic_sig,
                                         DexCodeScanResult& scan_result) {
  for (std::vector<uint32_t>::iterator i = logic_sig.not_crcs.begin();
       i != logic_sig.not_crcs.end(); ++i) {
    if (scan_result.HasCrc(*i)) return true;
  }
  return false;
}

// XOR fires only when *every* listed CRC is present, and GetMalwareSigIDs uses
// it as a veto. The loop short-circuits on the first miss, so count == size iff
// all matched.
bool DexCodeScanResultMgr::MatchXorLogic(DexCodeLogicSig& logic_sig,
                                         DexCodeScanResult& scan_result) {
  int count = 0;
  for (std::vector<uint32_t>::iterator i = logic_sig.xor_crcs.begin();
       i != logic_sig.xor_crcs.end(); ++i) {
    if (scan_result.HasCrc(*i))
      count++;
    else
      break;
  }
  if (logic_sig.xor_crcs.size() == count) return true;
  return false;
}

// AND is satisfied only when every listed CRC is present; the loop
// short-circuits on the first miss, so count == size iff all matched.
bool DexCodeScanResultMgr::MatchAndLogic(DexCodeLogicSig& logic_sig,
                                         DexCodeScanResult& scan_result) {
  int count = 0;
  for (std::vector<uint32_t>::iterator i = logic_sig.and_crcs.begin();
       i != logic_sig.and_crcs.end(); ++i) {
    if (scan_result.HasCrc(*i))
      count++;
    else
      break;
  }
  if (logic_sig.and_crcs.size() == count) return true;
  return false;
}

bool DexCodeScanResultMgr::MatchOrLogic(DexCodeLogicSig& logic_sig,
                                        DexCodeScanResult& scan_result) {
  for (std::vector<uint32_t>::iterator i = logic_sig.or_crcs.begin();
       i != logic_sig.or_crcs.end(); ++i) {
    if (scan_result.HasCrc(*i)) return true;
  }
  return false;
}

}  // namespace aav
