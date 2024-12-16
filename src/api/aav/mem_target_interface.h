#ifndef AAV_MEM_TARGET_INTERFACE_H_
#define AAV_MEM_TARGET_INTERFACE_H_

#include "aav/target_interface.h"

namespace aav {

struct MemSource;

// An ITarget over a caller-owned memory block; the buffer counterpart to
// IMemStream (e.g. a DEX extracted from an APK in RAM).
class IMemTarget : public ITarget {
 public:
  virtual int Init(MemSource* source) = 0;
  virtual int Uninit() = 0;
};

}  // namespace aav

#endif
