#ifndef AAV_DEX_DEX_PARSER_H_
#define AAV_DEX_DEX_PARSER_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

namespace aav {

class ITarget;
class DexSigMgr;
class DexFile;
class DexCode;
class DexPathScanResultMgr;
class DexCodeScanResultMgr;
struct DexAnalysisMethod;

struct DexCodeCRC {
  bool has_opcode;
  uint32_t opcode_crc;
  bool has_operand_str;
  uint32_t operand_str_crc;
};

class DexParser {
 public:
  DexParser();
  ~DexParser();

  int Init(DexSigMgr* sig_mgr, ITarget* target);
  int Uninit();
  int Scan(std::vector<uint32_t>& sig_id_array);

 private:
  int RegularizeClassName(std::string& class_name);
  int ScanMethod(DexCode& dex_code, DexCodeScanResultMgr& code_result_mgr,
                 bool analysis, DexAnalysisMethod* out);
  // Fills out.return_type/params from the method's proto (analysis only).
  void FillMethodProto(uint32_t method_index, DexAnalysisMethod& out);
  int GetCodeCrc(DexCode& dex_code, DexCodeCRC& code_crc);
  int MergeScanResult(DexPathScanResultMgr& path_result_mgr,
                      DexCodeScanResultMgr& code_result_mgr,
                      std::vector<uint32_t>& sig_id_array);

 private:
  DexSigMgr* dex_sig_mgr_;
  std::unique_ptr<DexFile> dex_file_;
};

}  // namespace aav

#endif
