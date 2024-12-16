#include "module.h"

#include <dlfcn.h>

namespace aav {

Module::Module() { handle_ = nullptr; }

Module::~Module() { Unload(); }

int Module::Load(const char* path) {
  if (nullptr == path || nullptr != handle_) return -1;
  // RTLD_LAZY defers symbol resolution to first use -- cheaper load, which is
  // the point of loading a heavy library on demand.
  handle_ = dlopen(path, RTLD_LAZY);
  return (nullptr != handle_) ? 0 : -1;
}

int Module::GetFuncAddress(const char* func_name, void** func_address) {
  if (nullptr == func_name || nullptr == func_address || nullptr == handle_)
    return -1;
  dlerror();  // clear any stale error so we can detect a genuine dlsym failure
  void* addr = dlsym(handle_, func_name);
  if (nullptr != dlerror() || nullptr == addr) return -1;
  *func_address = addr;
  return 0;
}

int Module::Unload() {
  int ret = 0;
  if (nullptr != handle_) {
    ret = dlclose(handle_);
    handle_ = nullptr;
  }
  return ret;
}

}  // namespace aav
