#ifndef AAV_PLATFORM_FILE_TARGET_H_
#define AAV_PLATFORM_FILE_TARGET_H_

#include <string>

#include "aav/file_target_interface.h"

namespace aav {

struct FileSource;

class FileMap;

// ITarget over an on-disk file: memory-maps it (via FileMap) and hands the
// parser a pointer to the whole image. The file counterpart to MemTarget.
class FileTarget final : public IFileTarget {
 public:
  FileTarget();
  ~FileTarget() override;

  int GetSize(int64_t* size) override;
  int GetName(char* name_buf, int name_buf_size) override;
  int GetFullPath(char* path_buf, int path_buf_size) override;
  int GetProperty(ScanObjectProperty* property) override;

  int GetBuf(void** buf) override;

  int Init(FileSource* source) override;
  int Uninit() override;

 private:
  int32_t mode_;
  std::string name_;
  std::string path_;
  FileMap* file_map_;
};

}  // namespace aav

#endif
