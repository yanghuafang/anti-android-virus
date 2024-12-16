#ifndef AAV_FILE_STREAM_INTERFACE_H_
#define AAV_FILE_STREAM_INTERFACE_H_

#include "aav/stream_interface.h"

namespace aav {

struct FileSource;

// An IStream over an on-disk file (the file counterpart to IMemStream).
class IFileStream : public IStream {
 public:
  virtual int Init(FileSource* source) = 0;
  virtual int Uninit() = 0;
};

}  // namespace aav

#endif
