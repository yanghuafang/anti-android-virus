#ifndef AAV_OBJECT_PTR_H_
#define AAV_OBJECT_PTR_H_

#include <memory>

#include "aav/object_interface.h"

// Internal RAII ownership for engine objects: an ObjPtr owns the object and
// releases it via IObject::Destroy() when it goes out of scope. This is an
// engine-internal helper and is deliberately NOT part of the public SDK surface
// (std::unique_ptr is not ABI-stable across compilers).
namespace aav {

struct ObjectReleaser {
  void operator()(IObject* p) const {
    if (p) p->Destroy();
  }
};

template <class T>
using ObjPtr = std::unique_ptr<T, ObjectReleaser>;

// Adopt an already-owned raw pointer into an ObjPtr.
template <class T>
ObjPtr<T> Adopt(IObject* raw) {
  return ObjPtr<T>(static_cast<T*>(raw));
}

}  // namespace aav

#endif
