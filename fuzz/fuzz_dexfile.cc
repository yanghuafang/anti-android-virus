// libFuzzer harness for the DEX parser (the untrusted-input attack surface).
//
// Build with clang:
//   cmake -S . -B build/fuzz -DAAV_BUILD_FUZZERS=ON
//   -DCMAKE_CXX_COMPILER=clang++ cmake --build build/fuzz --target fuzz_dexfile
//   ./build/fuzz/bin/fuzz_dexfile -max_total_time=60
#include <fcntl.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "aav/factory.h"
#include "aav/mem_source.h"
#include "aav/mem_target_interface.h"
#include "aav/object_interface.h"
#include "aav/object_ptr.h"
#include "dex_code.h"
#include "dex_code_sig_mgr.h"  // FastOpcodes
#include "dex_file.h"

using namespace aav;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 0x70) return 0;

  // Copy the input and stamp the header's magic/size/endian so the parser gets
  // past the trivial gate and into the table/offset parsing we want to fuzz.
  std::vector<uint8_t> buf(data, data + size);
  static const uint8_t kMagic[8] = {0x64, 0x65, 0x78, 0x0a,
                                    0x30, 0x33, 0x35, 0x00};
  memcpy(buf.data(), kMagic, 8);
  auto put32 = [&](size_t off, uint32_t v) {
    buf[off + 0] = uint8_t(v & 0xff);
    buf[off + 1] = uint8_t((v >> 8) & 0xff);
    buf[off + 2] = uint8_t((v >> 16) & 0xff);
    buf[off + 3] = uint8_t((v >> 24) & 0xff);
  };
  put32(32, static_cast<uint32_t>(buf.size()));  // file_size
  put32(36, 0x70);                               // header_size
  put32(40, 0x12345678);                         // endian_tag

  aav::ObjPtr<IMemTarget> target = aav::MakeMemtarget();
  if (!target) return 0;

  MemSource src;
  src.mode = O_RDONLY;
  src.name = "fuzz.dex";
  src.buf = buf.data();
  src.buf_size = static_cast<int>(buf.size());

  if (0 == target->Init(&src)) {
    DexFile df;
    if (0 == df.Init(target.get())) {
      std::string cls;
      int r;
      int classGuard = 0;
      while (-1 != (r = df.GetClass(cls)) && classGuard++ < 200000) {
        if (r == -2) continue;
        std::string name, proto;
        DexCode code;
        uint32_t key = 0;
        int mGuard = 0;
        while (-1 != (r = df.GetDirectMethod(name, proto, code, key)) &&
               mGuard++ < 200000) {
          if (r == -2) continue;
          FastOpcodes fo;
          code.GetFastOpcodes(fo);
          code.ParseCode();
        }
        key = 0;
        mGuard = 0;
        while (-1 != (r = df.GetVirtualMethod(name, proto, code, key)) &&
               mGuard++ < 200000) {
          if (r == -2) continue;
          FastOpcodes fo;
          code.GetFastOpcodes(fo);
          code.ParseCode();
        }
      }
    }
  }

  return 0;
}
