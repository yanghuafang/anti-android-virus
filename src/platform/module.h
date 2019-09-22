#ifndef AAV_PLATFORM_MODULE_H_
#define AAV_PLATFORM_MODULE_H_

#include <cstdint>

#include "aav/module_interface.h"

namespace aav {

// dlopen/dlsym/dlclose-backed IModule. Unloads on destruction.
class Module final : public IModule {
 public:
  Module();
  ~Module() override;

  int Load(const char* path) override;
  int GetFuncAddress(const char* func_name, void** func_address) override;
  int Unload() override;

 private:
  void* handle_;
};

}  // namespace aav

#endif
