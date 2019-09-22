#include <new>

#include "aav/factory.h"
#include "platform/module.h"

namespace aav {

ObjPtr<IModule> MakeModule() {
  return ObjPtr<IModule>(new (std::nothrow) Module);
}

}  // namespace aav
