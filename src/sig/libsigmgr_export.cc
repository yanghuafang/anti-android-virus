#include <new>

#include "aav/factory.h"
#include "sig/sig_mgr.h"

namespace aav {

ObjPtr<ISigMgr> MakeSigMgr() {
  return ObjPtr<ISigMgr>(new (std::nothrow) SigMgr);
}

}  // namespace aav
