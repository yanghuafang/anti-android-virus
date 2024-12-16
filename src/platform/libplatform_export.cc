#include <new>

#include "aav/factory.h"
#include "file_stream.h"
#include "file_system.h"
#include "file_target.h"
#include "mem_stream.h"
#include "mem_target.h"
#include "module.h"

namespace aav {

ObjPtr<IFileSystem> MakeFilesystem() {
  return ObjPtr<IFileSystem>(new (std::nothrow) FileSystem);
}

ObjPtr<IFileStream> MakeFilestream() {
  return ObjPtr<IFileStream>(new (std::nothrow) FileStream);
}

ObjPtr<IFileTarget> MakeFiletarget() {
  return ObjPtr<IFileTarget>(new (std::nothrow) FileTarget);
}

ObjPtr<IMemStream> MakeMemstream() {
  return ObjPtr<IMemStream>(new (std::nothrow) MemStream);
}

ObjPtr<IMemTarget> MakeMemtarget() {
  return ObjPtr<IMemTarget>(new (std::nothrow) MemTarget);
}

ObjPtr<IModule> MakeModule() {
  return ObjPtr<IModule>(new (std::nothrow) Module);
}

}  // namespace aav
