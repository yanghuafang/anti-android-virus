#include "dex_parser.h"

#include <stdio.h>

#include <algorithm>
#include <memory>
#include <new>
#include <utility>

#include "aav/target_interface.h"
#include "dex_analysis.h"
#include "dex_code.h"
#include "dex_code_scan_result_mgr.h"
#include "dex_code_sig_mgr.h"
#include "dex_file.h"
#include "dex_path_scan_result_mgr.h"
#include "dex_path_sig_mgr.h"
#include "dex_sig_mgr.h"
#include "log.h"

namespace aav {

DexParser::DexParser() { dex_sig_mgr_ = nullptr; }

DexParser::~DexParser() { Uninit(); }

int DexParser::Init(DexSigMgr* sig_mgr, ITarget* target) {
  if (nullptr == sig_mgr || nullptr == target) return -1;

  dex_sig_mgr_ = sig_mgr;
  dex_file_.reset(new (std::nothrow) DexFile);
  if (nullptr == dex_file_) return -1;
  if (0 != dex_file_->Init(target)) return -1;
  return 0;
}

int DexParser::Uninit() {
  dex_file_.reset();
  dex_sig_mgr_ = nullptr;
  return 0;
}

// Whole-file scan. Walk every class and apply the two matchers: a package-path
// hit (SearchClassPath) classifies the class outright; otherwise -- and always,
// in analysis mode -- walk its direct and virtual methods, reducing each to
// code features via ScanMethod. Path- and code-signature hits are then merged
// (MergeScanResult) into the confirmed sig_id list. Analysis mode additionally
// records a per-class feature tree instead of short-circuiting on a path hit.
int DexParser::Scan(std::vector<uint32_t>& sig_id_array) {
  const bool analysis = IsDexAnalysisEnabled();
  if (analysis) MutableDexAnalysisReport().classes.clear();

  std::string class_name;
  DexPathScanResultMgr path_result_mgr;
  DexCodeScanResultMgr code_result_mgr;
  int ret = 0;
  int result = 0;
  while (-1 != (result = dex_file_->GetClass(class_name))) {
    if (-2 == result) continue;
    if (0 != RegularizeClassName(class_name)) continue;
    AAV_LOGD("class: %s", class_name.c_str());

    // Analysis: record the class with its declared fields (and, below,
    // methods).
    DexAnalysisClass analysis_class;
    if (analysis) {
      analysis_class.class_path = class_name;
      ClassInfo class_info;
      if (0 == dex_file_->GetCurrentClassInfo(class_info)) {
        analysis_class.super_class = class_info.super_class;
        analysis_class.source_file = class_info.source_file;
      }
      std::vector<FieldInfo> fields;
      if (0 == dex_file_->GetCurrentClassFields(fields)) {
        for (const FieldInfo& fi : fields) {
          DexAnalysisField f;
          f.name = fi.name;
          f.type = fi.type;
          f.is_static = fi.is_static;
          analysis_class.fields.push_back(f);
        }
      }
    }

    DexPathSig* path_sig;
    if (0 == dex_sig_mgr_->SearchClassPath(class_name.c_str(), &path_sig)) {
      if (0 != path_result_mgr.AddSigHit(path_sig)) {
        ret = -1;
        break;
      }
      // A path hit already classifies the class; only keep walking its methods
      // when analysis wants every method's features recorded.
      if (!analysis) continue;
    }

    std::string method_name;
    std::string proto_name;
    DexCode dex_code;
    uint32_t key = 0;
    while (-1 != (result = dex_file_->GetDirectMethod(method_name, proto_name,
                                                      dex_code, key))) {
      if (-2 == result) continue;
      DexAnalysisMethod m;
      if (analysis) m.method_name = method_name;
      ScanMethod(dex_code, code_result_mgr, analysis, analysis ? &m : nullptr);
      if (analysis) {
        m.is_direct = true;
        FillMethodProto(key, m);
        analysis_class.methods.push_back(std::move(m));
      }
    }

    key = 0;
    while (-1 != (result = dex_file_->GetVirtualMethod(method_name, proto_name,
                                                       dex_code, key))) {
      if (-2 == result) continue;
      DexAnalysisMethod m;
      if (analysis) m.method_name = method_name;
      ScanMethod(dex_code, code_result_mgr, analysis, analysis ? &m : nullptr);
      if (analysis) {
        m.is_direct = false;
        FillMethodProto(key, m);
        analysis_class.methods.push_back(std::move(m));
      }
    }

    if (analysis)
      MutableDexAnalysisReport().classes.push_back(std::move(analysis_class));
  }

  if (0 != ret) return -1;
  return MergeScanResult(path_result_mgr, code_result_mgr, sig_id_array);
}

// Turn a DEX type descriptor ("Lcom/foo/Bar;") into the lower-cased, dotted
// form the path matcher keys on ("com.foo.bar"): drop the leading 'L' and
// trailing ';', map '/' to '.', and lower-case (path matching is
// case-insensitive).
int DexParser::RegularizeClassName(std::string& class_name) {
  if (0 == class_name.size()) return -1;

  if ('L' == class_name[0]) class_name.erase(0, 1);
  if (0 == class_name.size()) return -1;
  if (';' == class_name[class_name.size() - 1])
    class_name.erase(class_name.size() - 1, 1);
  if (0 == class_name.size()) return -1;

  for (int i = 0; i < class_name.size(); i++) {
    if (class_name[i] >= 0x41 && class_name[i] <= 0x5a)
      class_name[i] += 0x20;
    else if ('/' == class_name[i])
      class_name[i] = '.';
  }
  transform(class_name.begin(), class_name.end(), class_name.begin(),
            ::tolower);

  return 0;
}

int DexParser::ScanMethod(DexCode& dex_code,
                          DexCodeScanResultMgr& code_result_mgr, bool analysis,
                          DexAnalysisMethod* out) {
  FastOpcodes fast_opcodes;
  if (0 != dex_code.GetFastOpcodes(fast_opcodes)) return -1;

  // Fast opcode-bitmap pre-filter: in normal scans, skip methods that cannot
  // match any signature. In analysis mode every method is recorded, so the
  // pre-filter is bypassed.
  if (!analysis && 0 != dex_sig_mgr_->SearchOpcodeMap(&fast_opcodes)) return -1;

  if (0 != dex_code.ParseCode()) return -1;

  DexCodeCRC code_crc;
  GetCodeCrc(dex_code, code_crc);

  bool known = false;
  if (code_crc.has_opcode) {
    DexCodeCrcSig* opcode_sig = nullptr;
    if (0 == dex_sig_mgr_->SearchOpcodeCrc(code_crc.opcode_crc, &opcode_sig)) {
      known = true;
      if (0 != code_result_mgr.AddSigHit(opcode_sig)) return -1;
    }
  }

  if (code_crc.has_operand_str) {
    DexCodeCrcSig* operand_sig = nullptr;
    if (0 == dex_sig_mgr_->SearchOperandCrc(code_crc.operand_str_crc,
                                            &operand_sig)) {
      known = true;
      if (0 != code_result_mgr.AddSigHit(operand_sig)) return -1;
    }
  }

  if (analysis && nullptr != out) {
    out->known = known;
    out->has_opcode_crc = code_crc.has_opcode;
    out->opcode_crc = code_crc.opcode_crc;
    out->has_operand_crc = code_crc.has_operand_str;
    out->operand_crc = code_crc.operand_str_crc;
    dex_code.GetOperandStrings(out->strings);
  }
  return 0;
}

void DexParser::FillMethodProto(uint32_t method_index, DexAnalysisMethod& out) {
  MethodInfo method_info;
  if (0 == dex_file_->GetMethodInfo(method_index, method_info)) {
    out.return_type = method_info.proto_info.return_type;
    out.params = method_info.proto_info.parameters;
  }
}

int DexParser::GetCodeCrc(DexCode& dex_code, DexCodeCRC& code_crc) {
  if (0 != dex_code.GetOpcodeCrC32(code_crc.opcode_crc))
    code_crc.has_opcode = false;
  else
    code_crc.has_opcode = true;

  if (0 != dex_code.GetOperandStrCrC32(code_crc.operand_str_crc))
    code_crc.has_operand_str = false;
  else
    code_crc.has_operand_str = true;
  return 0;
}

// Combine the path-signature and code-signature hits into one de-duplicated
// sig_id list (their set union): either alone is a detection, and a sig_id
// found by both is reported once.
int DexParser::MergeScanResult(DexPathScanResultMgr& path_result_mgr,
                               DexCodeScanResultMgr& code_result_mgr,
                               std::vector<uint32_t>& sig_id_array) {
  std::vector<uint32_t> path_sig_id_array;
  if (0 != path_result_mgr.GetMalwareSigIDs(path_sig_id_array)) return -1;
  std::vector<uint32_t> code_sig_id_array;
  if (0 != code_result_mgr.GetMalwareSigIDs(dex_sig_mgr_, code_sig_id_array))
    return -1;

  try {
    if (code_sig_id_array.empty() && !path_sig_id_array.empty())
      sig_id_array = path_sig_id_array;
    if (path_sig_id_array.empty() && !code_sig_id_array.empty())
      sig_id_array = code_sig_id_array;
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
        if (!found) sig_id_array.push_back(*i);
      }
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexParser::MergeScanResult bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

}  // namespace aav
