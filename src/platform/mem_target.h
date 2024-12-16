#ifndef AAV_PLATFORM_MEM_TARGET_H_
#define AAV_PLATFORM_MEM_TARGET_H_

#include <string>

#include "aav/mem_target_interface.h"

namespace aav {

struct MemSource;

// ITarget over a caller-owned memory buffer (not copied or freed here). Used to
// scan a DEX already in RAM, e.g. one extracted from an APK.
class MemTarget : public IMemTarget {
 public:
  MemTarget();
  ~MemTarget();

  int GetSize(int64_t* size);
  int GetName(char* name_buf, int name_buf_size);
  int GetFullPath(char* path_buf, int path_buf_size);
  int GetProperty(ScanObjectProperty* property);

  int GetBuf(void** buf);

  int Init(MemSource* source);
  int Uninit();

 private:
  int32_t mode_;
  std::string name_;
  void* buf_;
  int buf_size_;
};

}  // namespace aav

#endif
