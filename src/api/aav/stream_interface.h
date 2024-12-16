#ifndef AAV_STREAM_INTERFACE_H_
#define AAV_STREAM_INTERFACE_H_

#include <stdint.h>

#include "aav/scan_object_interface.h"

namespace aav {

// A seekable byte stream over a file or a memory block. Used where content is
// read sequentially or unpacked -- notably archives (an APK/zip the scanner
// extracts entries from). Concrete: FileStream, MemStream.
class IStream : public IScanObject {
 public:
  virtual int Read(void* buf, int bytes_to_read, int* bytes_read) = 0;
  virtual int Write(void* buf, int bytes_to_write, int* bytes_written) = 0;
  virtual int SetSize(int64_t size) = 0;
  virtual int Flush() = 0;
  virtual int Seek(
      int64_t offset,
      int method) = 0;  // method 0: SEEK_SET 1: SEEK_CUR 2: SEEK_END
  virtual int Tell(int64_t* pos) = 0;

  // If the stream is backed by a contiguous region (a memory buffer, or a file
  // that can be memory-mapped), hand back a read-only pointer to the whole
  // content without copying and return 0. Return -1 if no such view is
  // available; callers must then fall back to Seek/Read. The view stays valid
  // until the stream is uninitialized or destroyed.
  virtual int GetView(const void** view, int64_t* size) = 0;
};

}  // namespace aav

#endif
