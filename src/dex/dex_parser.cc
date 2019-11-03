#include "dex/dex_parser.h"

#include <algorithm>
#include <cstdio>
#include <memory>
#include <new>
#include <utility>

#include "aav/target_interface.h"
#include "dex/dex_code.h"
#include "dex/dex_code_scan_result_mgr.h"
#include "dex/dex_code_sig_mgr.h"
#include "dex/dex_file.h"
#include "dex/dex_path_scan_result_mgr.h"
#include "dex/dex_path_sig_mgr.h"
#include "dex/dex_sig_mgr.h"
#include "utils/log.h"

namespace aav {

DexParser::DexParser() : dex_sig_mgr_(nullptr) {}

DexParser::~DexParser() { Uninit(); }

int DexParser::Init(DexSigMgr* sig_mgr, ITarget* target) {
  if (nullptr == sig_mgr || nullptr == target) {
    return -1;
  }

  dex_sig_mgr_ = sig_mgr;
  dex_file_.reset(new (std::nothrow) DexFile);
  if (nullptr == dex_file_) {
    return -1;
  }
  if (0 != dex_file_->Init(target)) {
    return -1;
  }
  return 0;
}

int DexParser::Uninit() {
  dex_file_.reset();
  dex_sig_mgr_ = nullptr;
  return 0;
}

// Whole-file scan. Walk every class and apply the two matchers: a package-path
// hit (SearchClassPath) classifies the class outright; otherwise walk its
// direct and virtual methods, reducing each to code features via ScanMethod.
// Path- and code-signature hits are then merged (MergeScanResult) into the
// confirmed sig_id list.
int DexParser::Scan(std::vector<uint32_t>& sig_id_array) {
  std::string class_name;
  DexPathScanResultMgr path_result_mgr;
  DexCodeScanResultMgr code_result_mgr;
  int ret = 0;
  int result = 0;
  while (-1 != (result = dex_file_->GetClass(class_name))) {
    if (-2 == result) {
      continue;
    }
    if (0 != RegularizeClassName(class_name)) {
      continue;
    }
    AAV_LOGD("class: %s", class_name.c_str());

    DexPathSig* path_sig = nullptr;
    if (0 == dex_sig_mgr_->SearchClassPath(class_name.c_str(), &path_sig)) {
      if (0 != path_result_mgr.AddSigHit(path_sig)) {
        ret = -1;
        break;
      }
      // A path hit already classifies the class; its methods add nothing.
      continue;
    }

    std::string method_name;
    std::string proto_name;
    DexCode dex_code;
    uint32_t key = 0;
    while (-1 != (result = dex_file_->GetDirectMethod(method_name, proto_name,
                                                      dex_code, key))) {
      if (-2 == result) {
        continue;
      }
      ScanMethod(dex_code, code_result_mgr);
    }

    key = 0;
    while (-1 != (result = dex_file_->GetVirtualMethod(method_name, proto_name,
                                                       dex_code, key))) {
      if (-2 == result) {
        continue;
      }
      ScanMethod(dex_code, code_result_mgr);
    }
  }

  if (0 != ret) {
    return -1;
  }
  return MergeScanResult(path_result_mgr, code_result_mgr, sig_id_array);
}

// Turn a DEX type descriptor ("Lcom/foo/Bar;") into the lower-cased, dotted
// form the path matcher keys on ("com.foo.bar"): drop the leading 'L' and
// trailing ';', map '/' to '.', and lower-case (path matching is
// case-insensitive).
int DexParser::RegularizeClassName(std::string& class_name) {
  if (class_name.empty()) {
    return -1;
  }

  if ('L' == class_name[0]) {
    class_name.erase(0, 1);
  }
  if (class_name.empty()) {
    return -1;
  }
  if (';' == class_name[class_name.size() - 1]) {
    class_name.erase(class_name.size() - 1, 1);
  }
  if (class_name.empty()) {
    return -1;
  }

  for (size_t i = 0; i < class_name.size(); i++) {
    if (class_name[i] >= 0x41 && class_name[i] <= 0x5a) {
      class_name[i] += 0x20;
    } else if ('/' == class_name[i]) {
      class_name[i] = '.';
    }
  }
  transform(class_name.begin(), class_name.end(), class_name.begin(),
            ::tolower);

  return 0;
}

int DexParser::ScanMethod(DexCode& dex_code,
                          DexCodeScanResultMgr& code_result_mgr) {
  FastOpcodes fast_opcodes;
  if (0 != dex_code.GetFastOpcodes(fast_opcodes)) {
    return -1;
  }

  // Fast opcode-bitmap pre-filter: skip methods that cannot match any
  // signature before paying for their CRCs.
  if (0 != dex_sig_mgr_->SearchOpcodeMap(&fast_opcodes)) {
    return -1;
  }

  if (0 != dex_code.ParseCode()) {
    return -1;
  }

  DexCodeCrc code_crc;
  GetCodeCrc(dex_code, code_crc);

  if (code_crc.has_opcode) {
    DexCodeCrcSig* opcode_sig = nullptr;
    if (0 == dex_sig_mgr_->SearchOpcodeCrc(code_crc.opcode_crc, &opcode_sig)) {
      if (0 != code_result_mgr.AddSigHit(opcode_sig)) {
        return -1;
      }
    }
  }

  if (code_crc.has_operand_str) {
    DexCodeCrcSig* operand_sig = nullptr;
    if (0 == dex_sig_mgr_->SearchOperandCrc(code_crc.operand_str_crc,
                                            &operand_sig)) {
      if (0 != code_result_mgr.AddSigHit(operand_sig)) {
        return -1;
      }
    }
  }
  return 0;
}

int DexParser::GetCodeCrc(DexCode& dex_code, DexCodeCrc& code_crc) {
  code_crc.has_opcode = 0 == dex_code.GetOpcodeCrC32(code_crc.opcode_crc);

  code_crc.has_operand_str =
      0 == dex_code.GetOperandStrCrC32(code_crc.operand_str_crc);
  return 0;
}

// Combine the path-signature and code-signature hits into one de-duplicated
// sig_id list (their set union): either alone is a detection, and a sig_id
// found by both is reported once.
int DexParser::MergeScanResult(DexPathScanResultMgr& path_result_mgr,
                               DexCodeScanResultMgr& code_result_mgr,
                               std::vector<uint32_t>& sig_id_array) {
  std::vector<uint32_t> path_sig_id_array;
  if (0 != path_result_mgr.GetMalwareSigIds(path_sig_id_array)) {
    return -1;
  }
  std::vector<uint32_t> code_sig_id_array;
  if (0 != code_result_mgr.GetMalwareSigIds(dex_sig_mgr_, code_sig_id_array)) {
    return -1;
  }

  try {
    if (code_sig_id_array.empty() && !path_sig_id_array.empty()) {
      sig_id_array = path_sig_id_array;
    }
    if (path_sig_id_array.empty() && !code_sig_id_array.empty()) {
      sig_id_array = code_sig_id_array;
    }
    if (!path_sig_id_array.empty() && !code_sig_id_array.empty()) {
      sig_id_array = code_sig_id_array;
      for (std::vector<uint32_t>::iterator i = path_sig_id_array.begin();
           i != path_sig_id_array.end(); ++i) {
        bool found = false;
        for (std::vector<uint32_t>::iterator j = code_sig_id_array.begin();
             j != code_sig_id_array.end(); ++j) {
          if (*j == *i) {
            found = true;
            break;
          }
        }
        if (!found) {
          sig_id_array.push_back(*i);
        }
      }
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexParser::MergeScanResult bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

}  // namespace aav
