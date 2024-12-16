#include "mem_target.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <new>

#include "aav/mem_source.h"
#include "aav/scan_object_property.h"

namespace aav {

MemTarget::MemTarget() {
  mode_ = 0;
  buf_ = nullptr;
  buf_size_ = 0;
}

MemTarget::~MemTarget() { Uninit(); }

int MemTarget::Init(MemSource* source) {
  if (nullptr == source) return -1;

  try {
    mode_ = source->mode;
    if (O_RDONLY != mode_ && O_WRONLY != mode_ && O_RDWR != mode_) return -1;

    if (nullptr != source->name) name_ = source->name;

    if (nullptr == source->buf) return -1;
    buf_ = static_cast<char*>(source->buf);

    if (0 == source->buf_size) return -1;
    buf_size_ = source->buf_size;
  } catch (std::bad_alloc& e) {
    return -1;
  }

  return 0;
}

int MemTarget::Uninit() {
  mode_ = 0;
  buf_ = nullptr;
  buf_size_ = 0;
  return 0;
}

int MemTarget::GetSize(int64_t* size) {
  if (nullptr == size) return -1;
  *size = buf_size_;
  return 0;
}

int MemTarget::GetName(char* name_buf, int name_buf_size) {
  if (nullptr == name_buf || name_buf_size < 1) return -1;

  memset(name_buf, 0, name_buf_size);
  strncpy(name_buf, name_.c_str(), name_buf_size - 1);
  return 0;
}

int MemTarget::GetFullPath(char* path_buf, int path_buf_size) { return 0; }

int MemTarget::GetProperty(ScanObjectProperty* property) {
  if (nullptr == property) return -1;

  property->unarch_layer = 0;
  property->unpack_layer = 0;
  return 0;
}

int MemTarget::GetBuf(void** buf) {
  if (nullptr == buf) return -1;

  *buf = buf_;
  return 0;
}

}  // namespace aav
