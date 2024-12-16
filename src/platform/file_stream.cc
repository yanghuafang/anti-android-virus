#include "file_stream.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <new>

#include "aav/file_source.h"
#include "aav/scan_object_property.h"
#include "file_map.h"
#include "log.h"

namespace aav {

FileStream::FileStream() {
  mode_ = 0;
  file_ = nullptr;
  file_map_ = nullptr;
}

FileStream::~FileStream() { Uninit(); }

int FileStream::Init(FileSource* source) {
  if (nullptr == source) return -1;

  try {
    mode_ = source->mode;
    if (O_RDONLY != mode_ && O_WRONLY != mode_ && O_RDWR != mode_) return -1;

    if (nullptr != source->name) name_ = source->name;

    if (nullptr == source->path) return -1;
    path_ = source->path;
  } catch (std::bad_alloc& e) {
    return -1;
  }

  switch (mode_) {
    case O_RDONLY:
      file_ = fopen(path_.c_str(), "r");
      break;
    case O_WRONLY:
      file_ = fopen(path_.c_str(), "w");
      break;
    case O_RDWR:
      file_ = fopen(path_.c_str(), "r+");
      break;
    default:
      break;
  }

  if (nullptr == file_) return -1;
  return 0;
}

int FileStream::Uninit() {
  mode_ = 0;

  if (nullptr != file_map_) {
    delete file_map_;
    file_map_ = nullptr;
  }
  if (nullptr != file_) {
    fclose(file_);
    file_ = nullptr;
  }
  return 0;
}

int FileStream::GetSize(int64_t* size) {
  int64_t pos = ftell(file_);
  if (-1 == pos) return -1;

  if (0 != fseek(file_, 0, SEEK_END)) return -1;
  *size = ftell(file_);

  if (0 != fseek(file_, pos, SEEK_SET)) {
    AAV_LOGE("FileStream::GetSize: fseek failed to restore position, aborting");
    abort();
    return -1;
  }

  if (-1 == *size) return -1;
  return 0;
}

int FileStream::GetName(char* name_buf, int name_buf_size) {
  if (nullptr == name_buf || name_buf_size < 1) return -1;

  memset(name_buf, 0, name_buf_size);
  strncpy(name_buf, name_.c_str(), name_buf_size - 1);
  return 0;
}

int FileStream::GetFullPath(char* path_buf, int path_buf_size) {
  if (nullptr == path_buf || path_buf_size < 1) return -1;

  memset(path_buf, 0, path_buf_size);
  strncpy(path_buf, path_.c_str(), path_buf_size - 1);
  return 0;
}

int FileStream::GetProperty(ScanObjectProperty* property) {
  if (nullptr == property) return -1;

  property->unarch_layer = 0;
  property->unpack_layer = 0;
  return 0;
}

int FileStream::Read(void* buf, int bytes_to_read, int* bytes_read) {
  if (nullptr == buf || nullptr == bytes_read || bytes_to_read < 1) return -1;

  *bytes_read = fread(buf, 1, bytes_to_read, file_);
  if (0 == *bytes_read) return -1;
  return 0;
}

int FileStream::Write(void* buf, int bytes_to_write, int* bytes_written) {
  if (nullptr == buf || nullptr == bytes_written || bytes_to_write < 1)
    return -1;

  *bytes_written = fwrite(buf, 1, bytes_to_write, file_);
  if (0 == *bytes_written) return -1;
  return 0;
}

int FileStream::SetSize(int64_t size) { return 0; }

int FileStream::Flush() { return 0; }

int FileStream::Seek(int64_t offset, int method) {
  if (SEEK_SET != method && SEEK_CUR != method && SEEK_END != method) return -1;

  if (0 == fseek(file_, offset, method)) return 0;
  return -1;
}

int FileStream::Tell(int64_t* pos) {
  *pos = ftell(file_);
  if (-1 == *pos) return -1;
  return 0;
}

int FileStream::GetView(const void** view, int64_t* size) {
  if (nullptr == view || nullptr == size) return -1;

  // Lazily memory-map the file the first time a view is requested; the mapping
  // is owned by this FileStream and released in Uninit.
  if (nullptr == file_map_) {
    file_map_ = new (std::nothrow) FileMap;
    if (nullptr == file_map_) return -1;
    if (0 != file_map_->Open(path_.c_str(), mode_)) {
      delete file_map_;
      file_map_ = nullptr;
      return -1;
    }
  }

  void* ptr = nullptr;
  int map_size = 0;
  if (0 != file_map_->GetPtr(&ptr) || 0 != file_map_->GetSize(&map_size))
    return -1;
  *view = ptr;
  *size = map_size;
  return 0;
}

}  // namespace aav
