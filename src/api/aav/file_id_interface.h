#ifndef AAV_FILE_ID_INTERFACE_H_
#define AAV_FILE_ID_INTERFACE_H_

#include "aav/object_interface.h"

namespace aav {

class IStream;
class ITarget;

enum FileType {
  kFileTypeUnknown = 0,

  // Android Dex
  kFileTypeDex = 10,
  kFileTypeOdex,

  // Linux format
  kFileTypeElf = 20,
  kFileTypeElF64,

  // Android OAT
  kFileTypeOat = 30,

  // Apple format
  kFileTypeMacho = 40,
  kFileTypeMachO64,

  // Microsoft format
  kFileTypePe = 50,
  kFileTypePE64,

  // archive format
  kFileTypeZip = 100,
};

enum PackType {
  kPackTypeUnknown = 0,
};

class IFileID : public IObject {
 public:
  virtual int Init(void* context) = 0;
  virtual int Uninit() = 0;
  virtual int GetFileType(IStream* stream, FileType* file_type) = 0;
  virtual int GetFileType(ITarget* target, FileType* file_type) = 0;
  virtual int GetPackType(IStream* stream, PackType* pack_type) = 0;
  virtual int GetPackType(ITarget* target, PackType* pack_type) = 0;
};

}  // namespace aav

#endif
