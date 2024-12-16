#ifndef AAV_SCAN_FILE_ID_H_
#define AAV_SCAN_FILE_ID_H_

#include "aav/file_id_interface.h"

namespace aav {

// File-type identification from magic bytes: distinguishes DEX vs ZIP/APK (and
// pack type) from the first bytes of a stream or target, so the engine can pick
// the right scanner.
class FileID : public IFileID {
 public:
  FileID();
  ~FileID();

  int Init(void* context);
  int Uninit();
  int GetFileType(IStream* stream, FileType* file_type);
  int GetFileType(ITarget* target, FileType* file_type);
  int GetPackType(IStream* stream, PackType* pack_type);
  int GetPackType(ITarget* target, PackType* pack_type);
};

}  // namespace aav

#endif
