#ifndef AAV_PLATFORM_FILE_STREAM_H_
#define AAV_PLATFORM_FILE_STREAM_H_

#include <stdio.h>

#include <string>

#include "aav/file_stream_interface.h"

namespace aav {

struct FileSource;
class FileMap;

// IStream over an on-disk file: buffered stdio for Read/Seek/Tell, plus a
// lazily memory-mapped view (GetView) for zero-copy whole-file access.
class FileStream : public IFileStream {
 public:
  FileStream();
  ~FileStream();

  int GetSize(int64_t* size);
  int GetName(char* name_buf, int name_buf_size);
  int GetFullPath(char* path_buf, int path_buf_size);
  int GetProperty(ScanObjectProperty* property);

  int Read(void* buf, int bytes_to_read, int* bytes_read);
  int Write(void* buf, int bytes_to_write, int* bytes_written);
  int SetSize(int64_t size);
  int Flush();
  int Seek(int64_t offset, int method);
  int Tell(int64_t* pos);
  int GetView(const void** view, int64_t* size);

  int Init(FileSource* source);
  int Uninit();

 private:
  int32_t mode_;
  std::string name_;
  std::string path_;
  FILE* file_;
  FileMap* file_map_;  // lazily created by GetView (mmap), owned here
};

}  // namespace aav

#endif
