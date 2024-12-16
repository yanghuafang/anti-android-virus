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
class IFileID;
class IScanner;
class ISigMgr;

// Object factories: construct engine objects. Each returns an owning ObjPtr
// (nullptr on allocation failure); ownership is RAII, there is no manual
// release. These are engine internals -- external consumers use MakeEngine.

// Signature database.
ObjPtr<ISigMgr> MakeSigmgr();

// File-type classification.
ObjPtr<IFileID> MakeFileid();

// Scanners.
ObjPtr<IScanner> MakeDexScanner();
ObjPtr<IScanner> MakeApkScanner();

// Platform I/O primitives.
ObjPtr<IFileSystem> MakeFilesystem();
ObjPtr<IFileStream> MakeFilestream();
ObjPtr<IFileTarget> MakeFiletarget();
ObjPtr<IMemStream> MakeMemstream();
ObjPtr<IMemTarget> MakeMemtarget();

// Dynamic-library loader.
ObjPtr<IModule> MakeModule();

}  // namespace aav

#endif
