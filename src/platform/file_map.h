#ifndef AAV_PLATFORM_FILE_MAP_H_
#define AAV_PLATFORM_FILE_MAP_H_

#include "aav/file_map_interface.h"

namespace aav {

// RAII wrapper around a read-only mmap of a file: Open maps it, Close/dtor
// unmaps. GetPtr/GetSize expose the mapping. Used by FileStream and FileTarget
// for zero-copy access to file contents.
class FileMap : public IFileMap {
 public:
  FileMap();
  ~FileMap();

  int Open(const char* path, int mode);
  int Close();
  int GetPtr(void** ptr);
  int GetSize(int* size);

 private:
  void* ptr_;
  int size_;
};

}  // namespace aav

#endif
