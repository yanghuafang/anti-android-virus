#include "dex_code.h"

#include <assert.h>
#include <stdio.h>

#include <algorithm>
#include <new>

#include "crc32.h"
#include "dex_code_sig_mgr.h"
#include "dex_file.h"
#include "log.h"

namespace aav {

const DexInstruction kInstructionFirstTable[] = {
    {0x00, 2},   // nop    //10x
    {0x01, 2},   // move vA, vB    //12x
    {0x02, 4},   // move/from16 vAA, vBBBB    //22x
    {0x03, 6},   // move/16 vAAAA, vBBBB    //32x
    {0x04, 2},   // move-wide vA, vB    //12x
    {0x05, 4},   // move-wide/from16 vAA, vBBBB    //22x
    {0x06, 6},   // move-wide/16 vAAAA, vBBBB    //32x
    {0x07, 2},   // move-object vA, vB     //12x
    {0x08, 4},   // move-object/from16 vAA, vBBBB    //22x
    {0x09, 6},   // move-object/16 vAAAA, vBBBB    //32x
    {0x0a, 2},   // move-result vAA    //11x
    {0x0b, 2},   // move-result-wide vAA    //11x
    {0x0c, 2},   // move-result-object vAA    //11x
    {0x0d, 2},   // move-exception vAA    //11x
    {0x0e, 2},   // return-void    //10x
    {0x0f, 2},   // return vAA    //11x
    {0x10, 2},   // return-wide vAA    //11x
    {0x11, 2},   // return-object vAA    //11x
    {0x12, 2},   // const/4 vA, #+B    //11n
    {0x13, 4},   // const/16 vAA, #+BBBB    //21s
    {0x14, 6},   // const vAA, #+BBBBBBBB    //31i
    {0x15, 4},   // const/high16 vAA, #+BBBB0000    //21h
    {0x16, 4},   // const-wide/16 vAA, #+BBBB    //21s
    {0x17, 6},   // const-wide/32 vAA, #+BBBBBBBB    //31i
    {0x18, 10},  // const-wide vAA, #+BBBBBBBBBBBBBBBB    //51l
    {0x19, 4},   // const-wide/high16 vAA, #+BBBB000000000000    //21h
    {0x1a, 4},   // const-string vAA, string@BBBB    //21c
    {0x1b, 6},   // const-string/jumbo vAA, string@BBBBBBBB    //31c
    {0x1c, 4},   // const-class vAA, type@BBBB    //21c
    {0x1d, 2},   // monitor-enter vAA    //11x
    {0x1e, 2},   // monitor-exit vAA    //11x
    {0x1f, 4},   // check-cast vAA, type@BBBB     //21c
    {0x20, 4},   // instance-of vA, vB, type@CCCC    //22c
    {0x21, 2},   // array-length vA, vB    //12x
    {0x22, 4},   // new-instance vAA, type@BBBB    //21c
    {0x23, 4},   // new-array vA, vB, type@CCCC    //22c
    {0x24, 6},   // filled-new-array {vC, vD, vE, vF, vG}, type@BBBB    //35c
    {0x25, 6},   // filled-new-array/range {vCCCC .. vNNNN}, type@BBBB    //3rc
    {0x26, 6},   // fill-array-data vAA, +BBBBBBBB (with supplemental data as
                // specified below in "fill-array-data-payload Format")    //31t
    {0x27, 2},  // throw vAA    //11x
    {0x28, 2},  // goto +AA    //10t
    {0x29, 4},  // goto/16 +AAAA    //20t
    {0x2a, 6},  // goto/32 +AAAAAAAA    //30t
    {0x2b, 6},  // packed-switch vAA, +BBBBBBBB (with supplemental data as
                // specified below in "packed-switch-payload Format")    //31t
    {0x2c, 6},  // sparse-switch vAA, +BBBBBBBB (with supplemental data as
                // specified below in "sparse-switch-payload Format")    //31t

    // 2d..31    //23x    //cmpkind vAA, vBB, vCC
    {0x2d, 4},  // cmpl-float
    {0x2e, 4},  // cmpg-float
    {0x2f, 4},  // cmpl-double
    {0x30, 4},  // cmpg-double
    {0x31, 4},  // cmp-long

    // 32..37    //22t    //if-test vA, vB, +CCCC
    {0x32, 4},  // if-eq
    {0x33, 4},  // if-ne
    {0x34, 4},  // if-lt
    {0x35, 4},  // if-ge
    {0x36, 4},  // if-gt
    {0x37, 4},  // if-le

    // 38..3d    //21t    //if-testz vAA, +BBBB
    {0x38, 4},  // if-eqz
    {0x39, 4},  // if-nez
    {0x3a, 4},  // if-ltz
    {0x3b, 4},  // if-gez
    {0x3c, 4},  // if-gtz
    {0x3d, 4},  // if-lez

    // 3e..43    //10x    //unused
    {0x3e, 2},
    {0x3f, 2},
    {0x40, 2},
    {0x41, 2},
    {0x42, 2},
    {0x43, 2},

    // 44..51    //23x    //arrayop vAA, vBB, vCC
    {0x44, 4},  // aget
    {0x45, 4},  // aget-wide
    {0x46, 4},  // aget-object
    {0x47, 4},  // aget-boolean
    {0x48, 4},  // aget-byte
    {0x49, 4},  // aget-char
    {0x4a, 4},  // aget-short
    {0x4b, 4},  // aput
    {0x4c, 4},  // aput-wide
    {0x4d, 4},  // aput-object
    {0x4e, 4},  // aput-boolean
    {0x4f, 4},  // aput-byte
    {0x50, 4},  // aput-char
    {0x51, 4},  // aput-short

    // 52..5f    //22c    //iinstanceop vA, vB, field@CCCC
    {0x52, 4},  // iget
    {0x53, 4},  // iget-wide
    {0x54, 4},  // iget-object
    {0x55, 4},  // iget-boolean
    {0x56, 4},  // iget-byte
    {0x57, 4},  // iget-char
    {0x58, 4},  // iget-short
    {0x59, 4},  // iput
    {0x5a, 4},  // iput-wide
    {0x5b, 4},  // iput-object
    {0x5c, 4},  // iput-boolean
    {0x5d, 4},  // iput-byte
    {0x5e, 4},  // iput-char
    {0x5f, 4},  // iput-short

    // 60..6d    //21c    //sstaticop vAA, field@BBBB
    {0x60, 4},  // sget
    {0x61, 4},  // sget-wide
    {0x62, 4},  // sget-object
    {0x63, 4},  // sget-boolean
    {0x64, 4},  // sget-byte
    {0x65, 4},  // sget-char
    {0x66, 4},  // sget-short
    {0x67, 4},  // sput
    {0x68, 4},  // sput-wide
    {0x69, 4},  // sput-object
    {0x6a, 4},  // sput-boolean
    {0x6b, 4},  // sput-byte
    {0x6c, 4},  // sput-char
    {0x6d, 4},  // sput-short

    // 6e..72    //35c    //invoke-kind {vC, vD, vE, vF, vG}, meth@BBBB
    {0x6e, 6},  // invoke-virtual
    {0x6f, 6},  // invoke-super
    {0x70, 6},  // invoke-direct
    {0x71, 6},  // invoke-static
    {0x72, 6},  // invoke-interface

    {0x73, 2},  // unused    //10x

    // 74..78    //3rc    //invoke-kind/range {vCCCC .. vNNNN}, meth@BBBB
    {0x74, 6},  // invoke-virtual/range
    {0x75, 6},  // invoke-super/range
    {0x76, 6},  // invoke-direct/range
    {0x77, 6},  // invoke-static/range
    {0x78, 6},  // invoke-interface/range

    // 79..7a    //10x    //unused
    {0x79, 2},
    {0x7a, 2},

    // 7b..8f    //12x    //unop vA, vB
    {0x7b, 2},  // neg-int
    {0x7c, 2},  // not-int
    {0x7d, 2},  // neg-long
    {0x7e, 2},  // not-long
    {0x7f, 2},  // neg-float
    {0x80, 2},  // net-double
    {0x81, 2},  // int-to-long
    {0x82, 2},  // int-to-float
    {0x83, 2},  // int-to-double
    {0x84, 2},  // long-to-int
    {0x85, 2},  // long-to-float
    {0x86, 2},  // long-to-double
    {0x87, 2},  // float-to-int
    {0x88, 2},  // float-to-long
    {0x89, 2},  // float-to-double
    {0x8a, 2},  // double-to-int
    {0x8b, 2},  // double-to-long
    {0x8c, 2},  // double-to-float
    {0x8d, 2},  // int-to-byte
    {0x8e, 2},  // int-to-char
    {0x8f, 2},  // int-to-short

    // 90..af    //23x    //binop vAA, vBB, vCC
    {0x90, 4},  // add-int
    {0x91, 4},  // sub-int
    {0x92, 4},  // mul-int
    {0x93, 4},  // div-int
    {0x94, 4},  // rem-int
    {0x95, 4},  // and-int
    {0x96, 4},  // or-int
    {0x97, 4},  // xor-int
    {0x98, 4},  // shl-int
    {0x99, 4},  // shr-int
    {0x9a, 4},  // ushr-int
    {0x9b, 4},  // add-long
    {0x9c, 4},  // sub-long
    {0x9d, 4},  // mul-long
    {0x9e, 4},  // div-long
    {0x9f, 4},  // rem-long
    {0xa0, 4},  // and-long
    {0xa1, 4},  // or-long
    {0xa2, 4},  // xor-long
    {0xa3, 4},  // shl-long
    {0xa4, 4},  // shr-long
    {0xa5, 4},  // ushr-long
    {0xa6, 4},  // add-float
    {0xa7, 4},  // sub-float
    {0xa8, 4},  // mul-float
    {0xa9, 4},  // div-float
    {0xaa, 4},  // rem-float
    {0xab, 4},  // add-double
    {0xac, 4},  // sub-double
    {0xad, 4},  // mul-double
    {0xae, 4},  // div-double
    {0xaf, 4},  // rem-double

    // b0..cf    //12x    //binop/2addr vA, vB
    {0xb0, 2},  // add-int/2addr
    {0xb1, 2},  // sub-int/2addr
    {0xb2, 2},  // mul-int/2addr
    {0xb3, 2},  // div-int/2addr
    {0xb4, 2},  // rem-int/2addr
    {0xb5, 2},  // and-int/2addr
    {0xb6, 2},  // or-int/2addr
    {0xb7, 2},  // xor-int/2addr
    {0xb8, 2},  // shl-int/2addr
    {0xb9, 2},  // shr-int/2addr
    {0xba, 2},  // ushr-int/2addr
    {0xbb, 2},  // add-long/2addr
    {0xbc, 2},  // sub-long/2addr
    {0xbd, 2},  // mul-long/2addr
    {0xbe, 2},  // div-long/2addr
    {0xbf, 2},  // rem-long/2addr
    {0xc0, 2},  // and-long/2addr
    {0xc1, 2},  // or-long/2addr
    {0xc2, 2},  // xor-long/2addr
    {0xc3, 2},  // shl-long/2addr
    {0xc4, 2},  // shr-long/2addr
    {0xc5, 2},  // ushr-long/2addr
    {0xc6, 2},  // add-float/2addr
    {0xc7, 2},  // sub-float/2addr
    {0xc8, 2},  // mul-float/2addr
    {0xc9, 2},  // div-float/2addr
    {0xca, 2},  // rem-float/2addr
    {0xcb, 2},  // add-double/2addr
    {0xcc, 2},  // sub-double/2addr
    {0xcd, 2},  // mul-double/2addr
    {0xce, 2},  // div-double/2addr
    {0xcf, 2},  // rem-double/2addr

    // d0..d7    //22a    //binop/lit16 vA, vB, #+CCCC
    {0xd0, 4},  // add-int/lit16
    {0xd1, 4},  // rsub-int (reverse subtract)
    {0xd2, 4},  // mul-int/lit16
    {0xd3, 4},  // div-int/lit16
    {0xd4, 4},  // rem-int/lit16
    {0xd5, 4},  // and-int/lit16
    {0xd6, 4},  // or-int/lit16
    {0xd7, 4},  // xor-int/lit16

    // d8..e2    //22b    //binop/lit8 vAA, vBB, #+CC
    {0xd8, 4},  // add-int/lit8
    {0xd9, 4},  // rsub-int/lit8
    {0xda, 4},  // mul-int/lit8
    {0xdb, 4},  // div-int/lit8
    {0xdc, 4},  // rem-int/lit8
    {0xdd, 4},  // and-int/lit8
    {0xde, 4},  // or-int/lit8
    {0xdf, 4},  // xor-int/lit8
    {0xe0, 4},  // shl-int/lit8
    {0xe1, 4},  // shr-int/lit8
    {0xe2, 4},  // ushr-int/lit8

    // e3..f9    //10x    //unused
    {0xe3, 2},
    {0xe4, 2},
    {0xe5, 2},
    {0xe6, 2},
    {0xe7, 2},
    {0xe8, 2},
    {0xe9, 2},
    {0xea, 2},
    {0xeb, 2},
    {0xec, 2},
    {0xed, 2},
    {0xee, 2},
    {0xef, 2},
    {0xf0, 2},
    {0xf1, 2},
    {0xf2, 2},
    {0xf3, 2},
    {0xf4, 2},
    {0xf5, 2},
    {0xf6, 2},
    {0xf7, 2},
    {0xf8, 2},
    {0xf9, 2},
    // fa..ff: the method-handle / invoke-custom family (DEX 038 = Android 8,
    // DEX 039 = Android 9). Each opcode has one fixed length, so the size table
    // still drives the instruction walk -- aav only needs to step over them.
    {0xfa, 8},  // invoke-polymorphic {vC..vG}, meth@BBBB, proto@HHHH    //45cc
    {0xfb, 8},  // invoke-polymorphic/range {vCCCC..vNNNN}, ...    //4rcc
    {0xfc, 6},  // invoke-custom {vC..vG}, call_site@BBBB    //35c
    {0xfd, 6},  // invoke-custom/range {vCCCC..vNNNN}, call_site@BBBB    //3rc
    {0xfe, 4},  // const-method-handle vAA, method_handle@BBBB    //21c
    {0xff, 4},  // const-method-type vAA, proto@BBBB    //21c
};

DexCode::DexCode() {
  dex_file_ = nullptr;
  func_start_ = nullptr;
  func_end_ = nullptr;
  code_end_ = nullptr;
  assert(0xff == kInstructionFirstTable[0xff].opcode);
}

DexCode::~DexCode() { Uninit(); }

int DexCode::Init(DexFile* dex_file, void* func_start, void* func_end) {
  if (nullptr == dex_file || nullptr == func_start || nullptr == func_end)
    return -1;
  if (func_start > func_end) return -1;

  dex_file_ = dex_file;
  func_start_ = func_start;
  func_end_ = func_end;
  code_end_ = func_end_;
  return 0;
}

int DexCode::Uninit() {
  dex_file_ = nullptr;
  func_start_ = nullptr;
  func_end_ = nullptr;
  code_end_ = nullptr;

  opcode_buf_.clear();
  operand_str_buf_.clear();
  return 0;
}

int DexCode::ParseCode() {
  uint8_t* cur = static_cast<uint8_t*>(func_start_);
  try {
    opcode_buf_.reserve(
        static_cast<size_t>(static_cast<uint8_t*>(code_end_) - cur) / 2);
    while (cur < static_cast<uint8_t*>(code_end_)) {
      uint8_t opcode = *cur;
      int size = kInstructionFirstTable[opcode].size;
      // The whole instruction must lie within the (possibly shrunk) code range.
      if (size <= 0 || cur + size > static_cast<uint8_t*>(code_end_)) break;

      opcode_buf_.push_back(opcode);

      // const-string (0x1a) and const-string/jumbo (0x1b) name a string by
      // index; collect the referenced text so it contributes to this method's
      // string-sequence feature (see PushOperandStr).
      if (0x1a == opcode || 0x1b == opcode) {
        uint32_t index = 0;
        if (0x1a == opcode)  // const-string vAA, string@BBBB
          index = *reinterpret_cast<uint16_t*>(cur + sizeof(uint16_t));
        else  // const-string/jumbo vAA, string@BBBBBBBB
          index = *reinterpret_cast<uint32_t*>(cur + sizeof(uint16_t));

        std::string const_str;
        int result = dex_file_->GetStringString(index, const_str);
        if (0 != result) return result;
        PushOperandStr(const_str);
      }

      // packed-switch (0x2b), sparse-switch (0x2c) and fill-array-data (0x26)
      // point at a data *payload* stored inline within the method body (at
      // cur + 2*payload_offset bytes). That payload is data, not code: if it
      // lies after the last real instruction, decoding its bytes as opcodes
      // would corrupt the feature. Clamp code_end_ to the earliest payload so
      // the walk stops before it. A payload outside the method is malformed.
      if (0x2b == opcode || 0x2c == opcode || 0x26 == opcode) {
        int32_t payload_offset =
            *reinterpret_cast<int32_t*>(cur + sizeof(uint16_t));
        uint8_t* payload_start = cur + sizeof(uint16_t) * payload_offset;
        if (payload_start >= static_cast<uint8_t*>(func_start_) &&
            payload_start < static_cast<uint8_t*>(func_end_)) {
          if (payload_start < static_cast<uint8_t*>(code_end_))
            code_end_ = payload_start;
        } else {
          return -2;
        }
      }

      cur += size;
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexCode::ParseCode bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

// The bitmap pre-filter keys off a method's first kFastOpcodesCount opcodes,
// packed pairwise into 16-bit values. Walk just far enough to collect them
// (applying the same inline-payload guard as ParseCode); a method with fewer
// real instructions can never match a code signature, so report failure.
int DexCode::GetFastOpcodes(FastOpcodes& fast_opcodes) {
  int real_count = 0;
  uint8_t opcodes[kFastOpcodesCount] = {0};
  uint8_t* cur = static_cast<uint8_t*>(func_start_);
  while (cur < static_cast<uint8_t*>(code_end_)) {
    uint8_t opcode = *cur;
    int size = kInstructionFirstTable[opcode].size;
    if (size <= 0 || cur + size > static_cast<uint8_t*>(code_end_)) break;

    if (opcode != 0xff &&
        (0x2b == opcode || 0x2c == opcode || 0x26 == opcode)) {
      int32_t payload_offset =
          *reinterpret_cast<int32_t*>(cur + sizeof(uint16_t));
      uint8_t* payload_start = cur + sizeof(uint16_t) * payload_offset;
      if (payload_start >= static_cast<uint8_t*>(func_start_) &&
          payload_start < static_cast<uint8_t*>(func_end_)) {
        if (payload_start < static_cast<uint8_t*>(code_end_))
          code_end_ = payload_start;
      } else {
        return -2;
      }
    }

    cur += size;
    opcodes[real_count] = opcode;
    real_count++;
    if (kFastOpcodesCount == real_count) break;
  }

  if (real_count < kFastOpcodesCount) return -1;
  fast_opcodes.opcode01 = *reinterpret_cast<uint16_t*>(&opcodes[0]);
  fast_opcodes.opcode23 = *reinterpret_cast<uint16_t*>(&opcodes[2]);
  fast_opcodes.opcode45 = *reinterpret_cast<uint16_t*>(&opcodes[4]);
  fast_opcodes.opcode67 = *reinterpret_cast<uint16_t*>(&opcodes[6]);
  return 0;
}

int DexCode::GetOpcodeCrC32(uint32_t& crc) {
  if (opcode_buf_.empty()) return -1;
  crc = Crc32(0, opcode_buf_.data(), static_cast<uint32_t>(opcode_buf_.size()));
  return 0;
}

int DexCode::GetOperandStrCrC32(uint32_t& crc) {
  if (operand_str_buf_.empty()) return -1;
  crc = Crc32(0, operand_str_buf_.data(),
              static_cast<uint32_t>(operand_str_buf_.size()));
  return 0;
}

// Normalize a referenced constant string, then append it (NUL-terminated) to
// the method's string-feature buffer. Lower-casing and trimming surrounding
// whitespace make the feature robust to trivial case/whitespace obfuscation;
// entirely-blank strings are dropped.
int DexCode::PushOperandStr(std::string& const_str) {
  transform(const_str.begin(), const_str.end(), const_str.begin(), ::tolower);
  int l = 0;
  int r = const_str.size() - 1;
  while (l <= r) {
    char lchar = const_str[l];
    bool lchar_valid = true;
    char rchar = const_str[r];
    bool rchar_valid = true;
    if (' ' == lchar || '\t' == lchar || '\x0d' == lchar || '\x0a' == lchar) {
      lchar_valid = false;
      l++;
    }
    if (' ' == rchar || '\t' == rchar || '\x0d' == rchar || '\x0a' == rchar) {
      rchar_valid = false;
      r--;
    }
    if (lchar_valid && rchar_valid) break;
  }
  if (l > r) return 0;

  try {
    const_str = const_str.substr(l, r - l + 1);
    for (int i = 0; i < const_str.size(); i++) {
      operand_str_buf_.push_back(const_str[i]);
    }
    operand_str_buf_.push_back(0);
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexCode::PushOperandStr bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

void DexCode::GetOperandStrings(std::vector<std::string>& out) const {
  out.clear();
  const char* p = operand_str_buf_.data();
  const char* end = p + operand_str_buf_.size();
  while (p < end) {
    // Each operand string was stored NUL-terminated by PushOperandStr.
    std::string s(p);
    p += s.size() + 1;
    out.push_back(s);
  }
}

}  // namespace aav
