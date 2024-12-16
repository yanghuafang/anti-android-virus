#ifndef AAV_MEM_STREAM_INTERFACE_H_
#define AAV_MEM_STREAM_INTERFACE_H_

#include "aav/stream_interface.h"

namespace aav {

struct MemSource;

// An IStream over a caller-owned memory block (e.g. an APK/zip held in RAM),
// the streaming counterpart to IMemTarget.
class IMemStream : public IStream {
 public:
  virtual int Init(MemSource* source) = 0;
  virtual int Uninit() = 0;
};

}  // namespace aav

#endif
