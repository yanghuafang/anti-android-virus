#ifndef AAV_FACTORY_H_
#define AAV_FACTORY_H_

#include "aav/object_ptr.h"

namespace aav {

class IModule;

// Object factories: construct engine objects. Each returns an owning ObjPtr
// (nullptr on allocation failure); ownership is RAII, there is no manual
// release. These are engine internals.

// Dynamic-library loader.
ObjPtr<IModule> MakeModule();

}  // namespace aav

#endif
