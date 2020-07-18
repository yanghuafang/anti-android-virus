#ifndef AAV_PLATFORM_FILE_STREAM_H_
#define AAV_PLATFORM_FILE_STREAM_H_

#include <cstdio>
#include <string>

#include "aav/file_stream_interface.h"

namespace aav {

struct FileSource;
class FileMap;

// IStream over an on-disk file: buffered stdio for Read/Seek/Tell, plus a
// lazily memory-mapped view (GetView) for zero-copy whole-file access.
class FileStream final : public IFileStream {
 public:
  FileStream();
  ~FileStream() override;

  int GetSize(int64_t* size) override;
  int GetName(char* name_buf, int name_buf_size) override;
  int GetFullPath(char* path_buf, int path_buf_size) override;
  int GetProperty(ScanObjectProperty* property) override;

  int Read(void* buf, int bytes_to_read, int* bytes_read) override;
  int Write(void* buf, int bytes_to_write, int* bytes_written) override;
  int SetSize(int64_t size) override;
  int Flush() override;
  int Seek(int64_t offset, int method) override;
  int Tell(int64_t* pos) override;
  int GetView(const void** view, int64_t* size) override;

  int Init(FileSource* source) override;
  int Uninit() override;

 private:
  int32_t mode_;
  std::string name_;
  std::string path_;
  std::FILE* file_;
  FileMap* file_map_;  // lazily created by GetView (mmap), owned here
};

}  // namespace aav

#endif
