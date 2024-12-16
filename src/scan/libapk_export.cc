#include <new>

#include "aav/factory.h"
#include "apk_scanner.h"

namespace aav {

ObjPtr<IScanner> MakeApkScanner() {
  return ObjPtr<IScanner>(new (std::nothrow) ApkScanner);
}

}  // namespace aav
