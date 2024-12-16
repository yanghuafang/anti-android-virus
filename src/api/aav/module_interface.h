#ifndef AAV_MODULE_INTERFACE_H_
#define AAV_MODULE_INTERFACE_H_

#include <stdint.h>

#include "aav/object_interface.h"

namespace aav {

// A dynamic-library (dlopen) handle. Enables lazy-loading a shared object at
// runtime (e.g. loading the engine, or an optional plugin, on demand instead of
// at process start) with RAII unload.
class IModule : public IObject {
 public:
  virtual int Load(const char* path) = 0;
  virtual int GetFuncAddress(const char* func_name, void** func_address) = 0;
  virtual int Unload() = 0;
};

}  // namespace aav

#endif
