#ifndef AAV_PLATFORM_FILE_SYSTEM_H_
#define AAV_PLATFORM_FILE_SYSTEM_H_

#include "aav/file_system_interface.h"

namespace aav {

class FileSystem : public IFileSystem {
 public:
  FileSystem();
  ~FileSystem();

  int CreateFile(const char* path);
  int RemoveFile(const char* path);
  int CopyFile(const char* src, const char* dst);
  int MoveFile(const char* src, const char* dst);
  bool FileExists(const char* path);
  int GetFileSize(const char* path, int64_t* file_size);
  int CreateTempFile(char* path_buf, int path_buf_size);

  int MakeDir(const char* path);
  int RemoveDir(const char* path);
  bool DirExists(const char* path);
  int GetCurrentDir(char* path_buf, int path_buf_size);
  int SetCurrentDir(const char* path);
};

}  // namespace aav

#endif
