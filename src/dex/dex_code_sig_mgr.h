#ifndef AAV_DEX_DEX_CODE_SIG_MGR_H_
#define AAV_DEX_DEX_CODE_SIG_MGR_H_

#include <stdint.h>

#include <bitset>
#include <vector>

#include "aav/sig_mgr_interface.h"
#include "dex_sig.h"

namespace aav {

struct SigItem;

class ISigMgr;

// Per-position allow-lists for the fast-opcode pre-filter (see FastOpcodes):
// mapNN has bit v set iff some signature permits value v as its NN-th key.
struct DexOpcodeMap {
  std::bitset<kBitMapSize> map01;
  std::bitset<kBitMapSize> map23;
  std::bitset<kBitMapSize> map45;
  std::bitset<kBitMapSize> map67;
};

struct DexCodeCrcSig {
  uint32_t crc;
  std::vector<uint32_t> sig_ids;
};

// The boolean expression for one sig_id over code CRCs, evaluated by
// DexCodeScanResultMgr (see its Match* helpers for the operator semantics).
struct DexCodeLogicSig {
  uint32_t sig_id;
  std::vector<uint32_t> not_crcs;
  std::vector<uint32_t> xor_crcs;
  std::vector<uint32_t> and_crcs;
  std::vector<uint32_t> or_crcs;
};

constexpr int kFastOpcodesCount = 8;

// A method's first kFastOpcodesCount opcodes packed pairwise into four 16-bit
// keys. Tested against DexOpcodeMap as a cheap pre-filter so methods that can't
// match any signature are skipped before the (costlier) CRC computation.
struct FastOpcodes {
  uint16_t opcode01;
  uint16_t opcode23;
  uint16_t opcode45;
  uint16_t opcode67;
};

// Owns the DEX code signature indexes, all built once from the DB in Init: the
// fast-opcode bitmap pre-filter, the opcode/operand CRC tables (binary-searched
// by SearchOpcodeCrc/SearchOperandCrc), and the per-sig boolean logic.
class DexCodeSigMgr {
 public:
  DexCodeSigMgr();
  ~DexCodeSigMgr();

  int Init(ISigMgr* sig_mgr);
  int Uninit();

  int SearchOpcodeMap(const FastOpcodes* opcodes);
  int SearchOpcodeCrc(uint32_t crc, DexCodeCrcSig** opcode_sig);
  int SearchOperandCrc(uint32_t crc, DexCodeCrcSig** operand_sig);
  int SearchCodeLogic(uint32_t sig_id, DexCodeLogicSig** logic_sig);

 private:
  int ParseOpcodeMap(const SigItem* opcode_map_item);
  int ParseOpcodeCrcSig(const SigItem* opcode_crc_sig_item);
  int ParseOperandCrcSig(const SigItem* operand_crc_sig_item);
  int ParseCodeLogicSig(const SigItem* code_logic_sig_item);

  int PrepareOpcodeMap(const uint8_t* map_in_file,
                       std::bitset<kBitMapSize>& map_in_mem);

 private:
  DexOpcodeMap opcode_map_;
  std::vector<DexCodeCrcSig> opcode_crc_sig_array_;
  std::vector<DexCodeCrcSig> operand_crc_sig_array_;
  std::vector<DexCodeLogicSig> code_logic_sig_array_;
};

}  // namespace aav

#endif
