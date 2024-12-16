#ifndef AAV_SCANNER_INTERFACE_H_
#define AAV_SCANNER_INTERFACE_H_

#include "aav/object_interface.h"
#include "aav/scan_result.h"

namespace aav {
class IStream;
class ITarget;

struct ScanOption;

enum ScannerId {
  kScannerIdUnknown = 0,
  kScannerIdApk,
  kScannerIdDex,
  kScannerIdElf,
  kScannerIdOat,
};

// A pluggable scanner for one container/format (DEX, APK, ...). The engine
// identifies a file's type and dispatches to the matching scanner: ScanStream
// for archives (IStream), ScanTarget for leaf images (ITarget). A scanner that
// doesn't support one input returns -1 for it (e.g. DexScanner has no
// ScanStream). Init receives shared context such as the signature manager.
class IScanner : public IObject {
 public:
  virtual int Init(void* context) = 0;
  virtual int Uninit() = 0;
  virtual int ScanStream(IStream* stream, const ScanOption* option,
                         ScanResultPtr& result) = 0;
  virtual int ScanTarget(ITarget* target, const ScanOption* option,
                         ScanResultPtr& result) = 0;
  virtual int GetScannerId(ScannerId* id) = 0;
};

}  // namespace aav

#endif
