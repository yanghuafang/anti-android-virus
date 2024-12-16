#ifndef AAV_TARGET_INTERFACE_H_
#define AAV_TARGET_INTERFACE_H_

#include "aav/scan_object_interface.h"

namespace aav {

// A scan "leaf" that exposes its entire content as one contiguous read-only
// buffer (GetBuf), so a parser can random-access the whole image -- used by the
// DEX parser. Contrast IStream, which is sequential. Concrete: FileTarget
// (mmap), MemTarget (caller buffer).
class ITarget : public IScanObject {
 public:
  virtual int GetBuf(void** buf) = 0;
};

}  // namespace aav

#endif
