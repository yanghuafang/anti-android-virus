#ifndef AAV_PLATFORM_MEM_STREAM_H_
#define AAV_PLATFORM_MEM_STREAM_H_

#include <cstdint>
#include <string>

#include "aav/mem_stream_interface.h"

namespace aav {

struct MemSource;
struct ScanObjectProperty;

// IStream backed by a caller-owned, fixed-size memory buffer, with a read/write
// cursor. The buffer is not copied or freed; the caller keeps it alive.
class MemStream final : public IMemStream {
 public:
  MemStream();
  ~MemStream() override;

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

  int Init(MemSource* source) override;
  int Uninit() override;

 private:
  int32_t mode_;
  std::string name_;
  char* buf_;
  int32_t buf_size_;
  int64_t pos_;
};

}  // namespace aav

#endif
