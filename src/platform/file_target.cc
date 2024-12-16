#include "file_target.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <new>

#include "aav/file_source.h"
#include "aav/scan_object_property.h"
#include "file_map.h"
#include "log.h"

namespace aav {

FileTarget::FileTarget() {
  mode_ = 0;
  file_map_ = nullptr;
}

FileTarget::~FileTarget() { Uninit(); }

int FileTarget::Init(FileSource* source) {
  if (nullptr == source) return -1;

  try {
    mode_ = source->mode;
    if (O_RDONLY != mode_ && O_WRONLY != mode_ && O_RDWR != mode_) return -1;

    if (nullptr != source->name) name_ = source->name;

    if (nullptr == source->path) return -1;
    path_ = source->path;
  } catch (std::bad_alloc& e) {
    AAV_LOGE("FileTarget::Init bad_alloc: %s", e.what());
    return -1;
  }

  file_map_ = new (std::nothrow) FileMap;
  if (nullptr == file_map_) {
    AAV_LOGE("FileTarget::Init failed to allocate FileMap");
    return -1;
  }
  return file_map_->Open(path_.c_str(), mode_);
}

int FileTarget::Uninit() {
  mode_ = 0;

  if (nullptr != file_map_) {
    delete file_map_;
    file_map_ = nullptr;
  }
  return 0;
}

int FileTarget::GetSize(int64_t* size) {
  int size32 = 0;
  int ret = file_map_->GetSize(&size32);
  if (0 != ret) return -1;
  *size = size32;
  return 0;
}

int FileTarget::GetName(char* name_buf, int name_buf_size) {
  if (nullptr == name_buf || name_buf_size < 1) return -1;

  memset(name_buf, 0, name_buf_size);
  strncpy(name_buf, name_.c_str(), name_buf_size - 1);
  return 0;
}

int FileTarget::GetFullPath(char* path_buf, int path_buf_size) {
  if (nullptr == path_buf || path_buf_size < 1) return -1;

  memset(path_buf, 0, path_buf_size);
  strncpy(path_buf, path_.c_str(), path_buf_size - 1);
  return 0;
}

int FileTarget::GetProperty(ScanObjectProperty* property) {
  if (nullptr == property) return -1;

  property->unarch_layer = 0;
  property->unpack_layer = 0;
  return 0;
}

int FileTarget::GetBuf(void** buf) { return file_map_->GetPtr(buf); }

}  // namespace aav
