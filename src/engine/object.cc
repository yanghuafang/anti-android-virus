#include "aav/object_interface.h"

// Defined out-of-line so destruction always runs inside the library: the caller
// of Destroy() never links operator delete for our objects, which is what keeps
// ownership ABI-safe across compilers/stdlib versions.
namespace aav {

void IObject::Destroy() { delete this; }

}  // namespace aav
