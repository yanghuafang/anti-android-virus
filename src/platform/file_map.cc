#include "file_map.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "log.h"

namespace aav {

namespace {
// Closes a file descriptor on scope exit, so Open() can early-return without a
// single-exit cleanup block.
struct FdGuard {
  int fd;
  explicit FdGuard(int f) : fd(f) {}
  ~FdGuard() {
    if (-1 != fd) ::close(fd);
  }
};
}  // namespace

FileMap::FileMap() {
  ptr_ = nullptr;
  size_ = 0;
}

FileMap::~FileMap() { Close(); }

int FileMap::Open(const char* path, int mode) {
  if (nullptr == path) return -1;
  if (O_RDONLY != mode && O_WRONLY != mode && O_RDWR != mode) return -1;

  FdGuard fd(::open(path, mode));
  if (-1 == fd.fd) {
    AAV_LOGE("failed to open file: %s errno: %d", path, errno);
    return -1;
  }

  struct stat st;
  if (0 != fstat(fd.fd, &st)) {
    AAV_LOGE("failed to fstat file: %s errno: %d", path, errno);
    return -1;
  }
  if (!(S_IFREG & st.st_mode)) {
    AAV_LOGE("%s is not a regular file", path);
    return -1;
  }

  void* p = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd.fd, 0);
  if (MAP_FAILED == p) {
    AAV_LOGE("failed to mmap file: %s size: %lld errno: %d", path,
             static_cast<long long>(st.st_size), errno);
    return -1;
  }
  ptr_ = p;
  size_ = st.st_size;
  return 0;
}

int FileMap::Close() {
  int ret = 0;
  if (nullptr != ptr_) {
    ret = munmap(ptr_, size_);
    ptr_ = nullptr;
    size_ = 0;
  }
  return ret;
}

int FileMap::GetPtr(void** ptr) {
  if (nullptr == ptr) return -1;
  if (nullptr == ptr_) return -1;

  *ptr = ptr_;
  return 0;
}

int FileMap::GetSize(int* size) {
  if (nullptr == size) return -1;

  *size = size_;
  return 0;
}

}  // namespace aav
