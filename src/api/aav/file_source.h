#ifndef AAV_FILE_SOURCE_H_
#define AAV_FILE_SOURCE_H_

#include <stdint.h>

namespace aav {

struct FileSource {
  int32_t mode;  // mode 0: O_RDONLY 1: O_WRONLY 2: O_RDWR
  const char* name;
  const char* path;
};

}  // namespace aav

#endif
