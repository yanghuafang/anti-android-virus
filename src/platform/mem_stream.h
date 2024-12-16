#ifndef AAV_PLATFORM_MEM_STREAM_H_
#define AAV_PLATFORM_MEM_STREAM_H_

#include <stdint.h>

#include <string>

#include "aav/mem_stream_interface.h"

namespace aav {

struct MemSource;
struct ScanObjectProperty;

// IStream backed by a caller-owned, fixed-size memory buffer, with a read/write
// cursor. The buffer is not copied or freed; the caller keeps it alive.
class MemStream : public IMemStream {
 public:
  MemStream();
  ~MemStream();

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

  int Init(MemSource* source);
  int Uninit();

 private:
  int32_t mode_;
  std::string name_;
  char* buf_;
  int32_t buf_size_;
  int64_t pos_;
};

}  // namespace aav

#endif
