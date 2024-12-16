#ifndef AAV_SCAN_APK_SCANNER_H_
#define AAV_SCAN_APK_SCANNER_H_

#include <stddef.h>

#include "aav/object_ptr.h"
#include "aav/scanner_interface.h"

namespace aav {

// Scans an APK (a zip container). It locates the app's classes.dex, then
// delegates the actual malware detection to a DEX scan of that entry. Both
// scanners share the caller-provided signature manager (passed to Init).
class ApkScanner : public IScanner {
 public:
  ApkScanner();
  ~ApkScanner();

  int Init(void* context);
  int Uninit();
  int ScanStream(IStream* stream, const ScanOption* option,
                 ScanResultPtr& result);
  int ScanTarget(ITarget* target, const ScanOption* option,
                 ScanResultPtr& result);
  int GetScannerId(ScannerId* id);

 private:
  // Extract classes.dex from an in-memory APK image and scan it as DEX.
  int ScanApkBytes(const void* data, size_t size, const ScanOption* option,
                   ScanResultPtr& result);

  ObjPtr<IScanner> dex_scanner_;
};

}  // namespace aav

#endif
