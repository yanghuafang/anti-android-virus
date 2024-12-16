#ifndef AAV_DEX_DEX_CODE_SCAN_RESULT_MGR_H_
#define AAV_DEX_DEX_CODE_SCAN_RESULT_MGR_H_

#include <stdint.h>

#include <list>
#include <vector>

namespace aav {

struct DexCodeCrcSig;
struct DexCodeLogicSig;

class DexCodeScanResult;
class DexSigMgr;

// Collects a file's DEX code-CRC hits and turns them into malware verdicts.
//
// As the parser matches opcode/operand CRCs, AddSigHit records, per candidate
// sig_id, the set of CRCs seen (one DexCodeScanResult each). GetMalwareSigIDs
// then evaluates each sig's DEX_CODE_LOGIC boolean expression over that set and
// returns the sig_ids that come out true. The Match* helpers are the four
// operators of that expression.
class DexCodeScanResultMgr {
 public:
  DexCodeScanResultMgr();
  ~DexCodeScanResultMgr();

  int AddSigHit(DexCodeCrcSig* code_sig);
  int GetMalwareSigIDs(DexSigMgr* code_sig_mgr,
                       std::vector<uint32_t>& sig_id_array);

 private:
  // NOT/OR are satisfied when *any* listed CRC is present; AND/XOR when *all*
  // are. In GetMalwareSigIDs, NOT and XOR act as vetoes (a satisfied one clears
  // the sig) while AND and OR are affirmative.
  bool MatchNotLogic(DexCodeLogicSig& logic_sig,
                     DexCodeScanResult& scan_result);
  bool MatchXorLogic(DexCodeLogicSig& logic_sig,
                     DexCodeScanResult& scan_result);
  bool MatchAndLogic(DexCodeLogicSig& logic_sig,
                     DexCodeScanResult& scan_result);
  bool MatchOrLogic(DexCodeLogicSig& logic_sig, DexCodeScanResult& scan_result);

 private:
  std::list<DexCodeScanResult> scan_result_list_;
};

}  // namespace aav

#endif
