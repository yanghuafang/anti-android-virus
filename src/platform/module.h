#ifndef AAV_PLATFORM_MODULE_H_
#define AAV_PLATFORM_MODULE_H_

#include <stdint.h>

#include "aav/module_interface.h"

namespace aav {

// dlopen/dlsym/dlclose-backed IModule. Unloads on destruction.
class Module : public IModule {
 public:
  Module();
  ~Module();

  int Load(const char* path);
  int GetFuncAddress(const char* func_name, void** func_address);
  int Unload();

 private:
  void* handle_;
};

}  // namespace aav

#endif
