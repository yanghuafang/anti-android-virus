#ifndef AAV_DEX_DEX_CODE_H_
#define AAV_DEX_DEX_CODE_H_

#include <stdint.h>

#include <string>
#include <vector>

namespace aav {

struct FastOpcodes;
class DexFile;

struct DexInstruction {
  uint16_t opcode;
  int size;
};

class DexCode {
 public:
  DexCode();
  ~DexCode();

  int Init(DexFile* dex_file, void* func_start, void* func_end);
  int Uninit();
  int ParseCode();
  int GetFastOpcodes(FastOpcodes& fast_opcodes);
  int GetOpcodeCrC32(uint32_t& crc);
  int GetOperandStrCrC32(uint32_t& crc);
  // Split the collected operand-string buffer into individual strings (for the
  // --analysis report). Empty when no const-strings were referenced.
  void GetOperandStrings(std::vector<std::string>& out) const;

 private:
  int PushOperandStr(std::string& const_str);

 private:
  DexFile* dex_file_;
  void* func_start_;
  void* func_end_;
  void* code_end_;
  std::vector<uint8_t> opcode_buf_;
  std::vector<char> operand_str_buf_;
};

}  // namespace aav

#endif
