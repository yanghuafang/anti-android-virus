#ifndef AAV_DEX_DEX_SIG_MGR_H_
#define AAV_DEX_DEX_SIG_MGR_H_

#include <stdint.h>

#include <memory>

namespace aav {

struct DexPathSig;
struct FastOpcodes;
struct DexCodeCrcSig;

class ISigMgr;
class DexPathSigMgr;
class DexCodeSigMgr;
class DexCodeLogicSig;

// Facade over the two DEX signature indexes, built once from the loaded DB:
// the class-path index (Aho-Corasick trie) and the code index (opcode bitmap
// pre-filter + CRC tables + boolean logic). The parser queries this; DexSigMgr
// just forwards each query to the appropriate sub-manager.
class DexSigMgr {
 public:
  DexSigMgr();
  ~DexSigMgr();

  int Init(ISigMgr* sig_mgr);
  int Uninit();

  int SearchClassPath(const char* class_path, DexPathSig** path_sig);
  int SearchOpcodeMap(const FastOpcodes* opcodes);
  int SearchOpcodeCrc(uint32_t crc, DexCodeCrcSig** opcode_sig);
  int SearchOperandCrc(uint32_t crc, DexCodeCrcSig** operand_sig);
  int SearchCodeLogic(uint32_t sig_id, DexCodeLogicSig** logic_sig);

 private:
  std::unique_ptr<DexPathSigMgr> path_sig_mgr_;
  std::unique_ptr<DexCodeSigMgr> code_sig_mgr_;
};

}  // namespace aav

#endif
