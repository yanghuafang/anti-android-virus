#ifndef AAV_PLATFORM_FILE_SYSTEM_H_
#define AAV_PLATFORM_FILE_SYSTEM_H_

#include "aav/file_system_interface.h"

namespace aav {

class FileSystem final : public IFileSystem {
 public:
  FileSystem();
  ~FileSystem() override;

  int CreateFile(const char* path) override;
  int RemoveFile(const char* path) override;
  int CopyFile(const char* src, const char* dst) override;
  int MoveFile(const char* src, const char* dst) override;
  bool FileExists(const char* path) override;
  int GetFileSize(const char* path, int64_t* file_size) override;
  int CreateTempFile(char* path_buf, int path_buf_size) override;

  int MakeDir(const char* path) override;
  int RemoveDir(const char* path) override;
  bool DirExists(const char* path) override;
  int GetCurrentDir(char* path_buf, int path_buf_size) override;
  int SetCurrentDir(const char* path) override;
};

}  // namespace aav

#endif
