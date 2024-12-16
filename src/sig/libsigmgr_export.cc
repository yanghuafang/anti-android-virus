#include <new>

#include "aav/factory.h"
#include "sig_mgr.h"

namespace aav {

ObjPtr<ISigMgr> MakeSigmgr() {
  return ObjPtr<ISigMgr>(new (std::nothrow) SigMgr);
}

}  // namespace aav
