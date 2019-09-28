#ifndef AAV_FACTORY_H_
#define AAV_FACTORY_H_

#include "aav/object_ptr.h"

namespace aav {

class IFileStream;
class IFileTarget;
class IFileSystem;
class IMemStream;
class IMemTarget;
class IModule;

// Object factories: construct engine objects. Each returns an owning ObjPtr
// (nullptr on allocation failure); ownership is RAII, there is no manual
// release. These are engine internals.

// Platform I/O primitives.
ObjPtr<IFileSystem> MakeFileSystem();
ObjPtr<IFileStream> MakeFileStream();
ObjPtr<IFileTarget> MakeFileTarget();
ObjPtr<IMemStream> MakeMemStream();
ObjPtr<IMemTarget> MakeMemTarget();

// Dynamic-library loader.
ObjPtr<IModule> MakeModule();

}  // namespace aav

#endif
