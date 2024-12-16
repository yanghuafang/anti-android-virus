#include "dex_sig_mgr.h"

#include <memory>
#include <new>

#include "dex_code_sig_mgr.h"
#include "dex_path_sig_mgr.h"
#include "log.h"

namespace aav {

DexSigMgr::DexSigMgr() {}

DexSigMgr::~DexSigMgr() { Uninit(); }

int DexSigMgr::Init(ISigMgr* sig_mgr) {
  if (nullptr == sig_mgr) return -1;

  path_sig_mgr_.reset(new (std::nothrow) DexPathSigMgr);
  if (nullptr == path_sig_mgr_) return -1;
  if (0 != path_sig_mgr_->Init(sig_mgr)) {
    AAV_LOGE("DexSigMgr::Init path_sig_mgr_ init failed");
    return -1;
  }

  code_sig_mgr_.reset(new (std::nothrow) DexCodeSigMgr);
  if (nullptr == code_sig_mgr_) return -1;
  if (0 != code_sig_mgr_->Init(sig_mgr)) {
    AAV_LOGE("DexSigMgr::Init code_sig_mgr_ init failed");
    return -1;
  }

  return 0;
}

int DexSigMgr::Uninit() {
  path_sig_mgr_.reset();
  code_sig_mgr_.reset();
  return 0;
}

int DexSigMgr::SearchClassPath(const char* class_path, DexPathSig** path_sig) {
  return path_sig_mgr_->SearchClassPath(class_path, path_sig);
}

int DexSigMgr::SearchOpcodeMap(const FastOpcodes* opcodes) {
  return code_sig_mgr_->SearchOpcodeMap(opcodes);
}

int DexSigMgr::SearchOpcodeCrc(uint32_t crc, DexCodeCrcSig** opcode_sig) {
  return code_sig_mgr_->SearchOpcodeCrc(crc, opcode_sig);
}

int DexSigMgr::SearchOperandCrc(uint32_t crc, DexCodeCrcSig** operand_sig) {
  return code_sig_mgr_->SearchOperandCrc(crc, operand_sig);
}

int DexSigMgr::SearchCodeLogic(uint32_t sig_id, DexCodeLogicSig** logic_sig) {
  return code_sig_mgr_->SearchCodeLogic(sig_id, logic_sig);
}

}  // namespace aav
