#include <new>

#include "aav/factory.h"
#include "file_id.h"

namespace aav {

ObjPtr<IFileID> MakeFileid() {
  return ObjPtr<IFileID>(new (std::nothrow) FileID);
}

}  // namespace aav
