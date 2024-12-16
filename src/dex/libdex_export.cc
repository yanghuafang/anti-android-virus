#include <new>

#include "aav/factory.h"
#include "dex_scanner.h"

namespace aav {

ObjPtr<IScanner> MakeDexScanner() {
  return ObjPtr<IScanner>(new (std::nothrow) DexScanner);
}

}  // namespace aav
