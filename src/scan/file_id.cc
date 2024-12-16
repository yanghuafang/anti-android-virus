#include "file_id.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <new>

#include "aav/stream_interface.h"
#include "aav/target_interface.h"

namespace aav {

namespace {
// The DEX magic is "dex\n0XY\0"; accept versions 035..040 (Android 1.0..10+).
// The container and its id/class tables are identical across these versions
// (only tail opcodes and side tables differ), so identification is
// version-agnostic here.
bool IsDexMagic(const void* buf) {
  const uint8_t* p = static_cast<const uint8_t*>(buf);
  static const uint8_t kPrefix[4] = {0x64, 0x65, 0x78, 0x0a};  // "dex\n"
  if (0 != memcmp(p, kPrefix, 4)) return false;
  if (0x00 != p[7]) return false;
  if ('0' != p[4]) return false;
  if ('3' == p[5] && p[6] >= '5' && p[6] <= '9') return true;  // 035..039
  if ('4' == p[5] && '0' == p[6]) return true;                 // 040
  return false;
}
}  // namespace

FileID::FileID() {}

FileID::~FileID() { Uninit(); }

int FileID::Init(void* context) { return 0; }

int FileID::Uninit() { return 0; }

int FileID::GetFileType(IStream* stream, FileType* file_type) {
  if (nullptr == stream || nullptr == file_type) return -1;

  int64_t file_size = 0;
  if (0 != stream->GetSize(&file_size)) return -1;
  if (file_size < 16) return -1;

  char buf[16] = {0};
  int bytes_read = 0;
  if (0 != stream->Read(buf, sizeof(buf), &bytes_read)) return -1;

  if (IsDexMagic(buf)) {
    *file_type = kFileTypeDex;
    return 0;
  }

  uint8_t zip_file_magic[4] = {0x50, 0x4b, 0x03, 0x04};
  if (0 == memcmp(buf, zip_file_magic, sizeof(zip_file_magic))) {
    *file_type = kFileTypeZip;
    return 0;
  }

  *file_type = kFileTypeUnknown;
  return -1;
}

int FileID::GetFileType(ITarget* target, FileType* file_type) {
  if (nullptr == target || nullptr == file_type) return -1;

  int64_t file_size = 0;
  if (0 != target->GetSize(&file_size)) return -1;
  if (file_size < 16) return -1;

  void* buf = nullptr;
  if (0 != target->GetBuf(&buf)) return -1;

  if (IsDexMagic(buf)) {
    *file_type = kFileTypeDex;
    return 0;
  }

  uint8_t zip_file_magic[4] = {0x50, 0x4b, 0x03, 0x04};
  if (0 == memcmp(buf, zip_file_magic, sizeof(zip_file_magic))) {
    *file_type = kFileTypeZip;
    return 0;
  }

  *file_type = kFileTypeUnknown;
  return -1;
}

int FileID::GetPackType(IStream* stream, PackType* pack_type) {
  if (nullptr == stream || nullptr == pack_type) return -1;
  *pack_type = kPackTypeUnknown;
  return 0;
}

int FileID::GetPackType(ITarget* target, PackType* pack_type) {
  if (nullptr == target || nullptr == pack_type) return -1;
  *pack_type = kPackTypeUnknown;
  return 0;
}

}  // namespace aav
