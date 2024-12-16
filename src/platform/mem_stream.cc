#include "mem_stream.h"

#include <fcntl.h>
#include <string.h>

#include "aav/mem_source.h"
#include "aav/scan_object_property.h"

namespace aav {

MemStream::MemStream() {
  mode_ = 0;
  buf_ = nullptr;
  buf_size_ = 0;
  pos_ = 0;
}

MemStream::~MemStream() { Uninit(); }

int MemStream::Init(MemSource* source) {
  if (nullptr == source) return -1;
  mode_ = source->mode;
  if (O_RDONLY != mode_ && O_WRONLY != mode_ && O_RDWR != mode_) return -1;
  if (nullptr != source->name) name_ = source->name;
  if (nullptr == source->buf) return -1;
  buf_ = static_cast<char*>(source->buf);
  if (0 == source->buf_size) return -1;
  buf_size_ = source->buf_size;
  pos_ = 0;
  return 0;
}

int MemStream::Uninit() {
  mode_ = 0;
  buf_ = nullptr;
  buf_size_ = 0;
  pos_ = 0;
  return 0;
}

int MemStream::GetSize(int64_t* size) {
  if (nullptr == size) return -1;
  *size = buf_size_;
  return 0;
}

int MemStream::GetName(char* name_buf, int name_buf_size) {
  if (nullptr == name_buf || name_buf_size < 1) return -1;
  memset(name_buf, 0, name_buf_size);
  strncpy(name_buf, name_.c_str(), name_buf_size - 1);
  return 0;
}

int MemStream::GetFullPath(char* path_buf, int path_buf_size) { return 0; }

int MemStream::GetProperty(ScanObjectProperty* property) {
  if (nullptr == property) return -1;
  property->unarch_layer = 0;
  property->unpack_layer = 0;
  return 0;
}

int MemStream::Read(void* buf, int bytes_to_read, int* bytes_read) {
  if (nullptr == buf || nullptr == bytes_read || bytes_to_read < 1 ||
      nullptr == buf_)
    return -1;
  int64_t bytes_left = buf_size_ - pos_;
  if (bytes_left <= 0) return -1;  // EOF
  int n =
      bytes_to_read < bytes_left ? bytes_to_read : static_cast<int>(bytes_left);
  memcpy(buf, buf_ + pos_, n);
  *bytes_read = n;
  pos_ += n;
  return 0;
}

int MemStream::Write(void* buf, int bytes_to_write, int* bytes_written) {
  if (nullptr == buf || nullptr == bytes_written || bytes_to_write < 1 ||
      nullptr == buf_)
    return -1;
  if (O_RDONLY == mode_) return -1;
  int64_t bytes_left = buf_size_ - pos_;
  if (bytes_left <= 0) return -1;
  int n = bytes_to_write < bytes_left ? bytes_to_write
                                      : static_cast<int>(bytes_left);
  memcpy(buf_ + pos_, buf, n);
  *bytes_written = n;
  pos_ += n;
  return 0;
}

int MemStream::SetSize(int64_t size) { return 0; }

int MemStream::Flush() { return 0; }

int MemStream::Seek(int64_t offset, int method) {
  int64_t base = 0;
  switch (method) {
    case 0:  // SEEK_SET
      base = 0;
      break;
    case 1:  // SEEK_CUR
      base = pos_;
      break;
    case 2:  // SEEK_END
      base = buf_size_;
      break;
    default:
      return -1;
  }
  int64_t next = base + offset;
  if (next < 0 || next > buf_size_) return -1;
  pos_ = next;
  return 0;
}

int MemStream::Tell(int64_t* pos) {
  if (nullptr == pos) return -1;
  *pos = pos_;
  return 0;
}

int MemStream::GetView(const void** view, int64_t* size) {
  if (nullptr == view || nullptr == size || nullptr == buf_) return -1;
  // The memory block is already contiguous -- hand it back directly, no copy.
  *view = buf_;
  *size = buf_size_;
  return 0;
}

}  // namespace aav
