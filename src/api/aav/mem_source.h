#ifndef AAV_MEM_SOURCE_H_
#define AAV_MEM_SOURCE_H_

#include <stdint.h>

namespace aav {

struct MemSource {
  int32_t mode;  // mode 0: O_RDONLY 1: O_WRONLY 2: O_RDWR
  const char* name;
  void* buf;
  int32_t buf_size;
};

}  // namespace aav

#endif
