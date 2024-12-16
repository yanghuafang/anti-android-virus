#ifndef AAV_FILE_TARGET_INTERFACE_H_
#define AAV_FILE_TARGET_INTERFACE_H_

#include "aav/target_interface.h"

namespace aav {

struct FileSource;

// An ITarget over an on-disk file, exposing its mmap'd contents as one buffer.
class IFileTarget : public ITarget {
 public:
  virtual int Init(FileSource* source) = 0;
  virtual int Uninit() = 0;
};

}  // namespace aav

#endif
