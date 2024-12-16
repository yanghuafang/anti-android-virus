#ifndef AAV_FILE_MAP_INTERFACE_H_
#define AAV_FILE_MAP_INTERFACE_H_

#include <stdint.h>

#include "aav/object_interface.h"

namespace aav {

class IFileMap : public IObject {
 public:
  virtual int Open(const char* path,
                   int mode) = 0;  // mode 0: O_RDONLY 1: O_WRONLY 2: O_RDWR
  virtual int Close() = 0;
  virtual int GetPtr(void** ptr) = 0;
  virtual int GetSize(int* size) = 0;
};

}  // namespace aav

#endif
