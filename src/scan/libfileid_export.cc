#include <new>

#include "aav/factory.h"
#include "scan/file_id.h"

namespace aav {

ObjPtr<IFileId> MakeFileId() {
  return ObjPtr<IFileId>(new (std::nothrow) FileId);
}

}  // namespace aav
