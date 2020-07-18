#include <new>

#include "aav/factory.h"
#include "platform/file_stream.h"
#include "platform/file_system.h"
#include "platform/file_target.h"
#include "platform/mem_stream.h"
#include "platform/mem_target.h"
#include "platform/module.h"

namespace aav {

ObjPtr<IFileSystem> MakeFileSystem() {
  return ObjPtr<IFileSystem>(new (std::nothrow) FileSystem);
}

ObjPtr<IFileStream> MakeFileStream() {
  return ObjPtr<IFileStream>(new (std::nothrow) FileStream);
}

ObjPtr<IFileTarget> MakeFileTarget() {
  return ObjPtr<IFileTarget>(new (std::nothrow) FileTarget);
}

ObjPtr<IMemStream> MakeMemStream() {
  return ObjPtr<IMemStream>(new (std::nothrow) MemStream);
}

ObjPtr<IMemTarget> MakeMemTarget() {
  return ObjPtr<IMemTarget>(new (std::nothrow) MemTarget);
}

ObjPtr<IModule> MakeModule() {
  return ObjPtr<IModule>(new (std::nothrow) Module);
}

}  // namespace aav
