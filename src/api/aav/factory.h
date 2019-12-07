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
class IFileId;
class IScanner;
class ISigMgr;

// Object factories: construct engine objects. Each returns an owning ObjPtr
// (nullptr on allocation failure); ownership is RAII, there is no manual
// release. These are engine internals -- external consumers use MakeEngine.

// Signature database.
ObjPtr<ISigMgr> MakeSigMgr();

// File-type classification.
ObjPtr<IFileId> MakeFileId();

// Scanners.
ObjPtr<IScanner> MakeDexScanner();
ObjPtr<IScanner> MakeApkScanner();

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
