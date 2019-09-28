#ifndef AAV_PLATFORM_MEM_TARGET_H_
#define AAV_PLATFORM_MEM_TARGET_H_

#include <string>

#include "aav/mem_target_interface.h"

namespace aav {

struct MemSource;

// ITarget over a caller-owned memory buffer (not copied or freed here). Used to
// scan a DEX already in RAM, e.g. one extracted from an APK.
class MemTarget final : public IMemTarget {
 public:
  MemTarget();
  ~MemTarget() override;

  int GetSize(int64_t* size) override;
  int GetName(char* name_buf, int name_buf_size) override;
  int GetFullPath(char* path_buf, int path_buf_size) override;
  int GetProperty(ScanObjectProperty* property) override;

  int GetBuf(void** buf) override;

  int Init(MemSource* source) override;
  int Uninit() override;

 private:
  int32_t mode_;
  std::string name_;
  void* buf_;
  int buf_size_;
};

}  // namespace aav

#endif
