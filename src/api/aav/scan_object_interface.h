#ifndef AAV_SCAN_OBJECT_INTERFACE_H_
#define AAV_SCAN_OBJECT_INTERFACE_H_

#include <stdint.h>

#include "aav/object_interface.h"

namespace aav {
struct ScanObjectProperty;

// Common base for anything the engine can scan: a named object with a size and
// properties. It has two subfamilies that give scanners uniform access to both
// on-disk files and in-memory buffers -- IStream (sequential/seekable, for
// archives) and ITarget (whole-content buffer, for leaf images like DEX).
class IScanObject : public IObject {
 public:
  virtual int GetSize(int64_t* size) = 0;
  virtual int GetName(char* name_buf, int name_buf_size) = 0;
  virtual int GetFullPath(char* path_buf, int path_buf_size) = 0;
  virtual int GetProperty(ScanObjectProperty* property) = 0;
};

}  // namespace aav

#endif
