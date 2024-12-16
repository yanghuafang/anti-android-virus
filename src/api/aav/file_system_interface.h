#ifndef AAV_FILE_SYSTEM_INTERFACE_H_
#define AAV_FILE_SYSTEM_INTERFACE_H_

#include <stdint.h>

#include "aav/object_interface.h"

namespace aav {
class IStream;
class ITarget;

class IFileSystem : public IObject {
 public:
  virtual int CreateFile(const char* path) = 0;
  virtual int RemoveFile(const char* path) = 0;
  virtual int CopyFile(const char* src, const char* dst) = 0;
  virtual int MoveFile(const char* src, const char* dst) = 0;
  virtual bool FileExists(const char* path) = 0;
  virtual int GetFileSize(const char* path, int64_t* file_size) = 0;
  virtual int CreateTempFile(char* path_buf, int path_buf_size) = 0;

  virtual int MakeDir(const char* path) = 0;
  virtual int RemoveDir(const char* path) = 0;
  virtual bool DirExists(const char* path) = 0;
  virtual int GetCurrentDir(char* path_buf, int path_buf_size) = 0;
  virtual int SetCurrentDir(const char* path) = 0;
};

}  // namespace aav

#endif
