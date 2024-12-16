#ifndef AAV_DEX_DEX_SCANNER_H_
#define AAV_DEX_DEX_SCANNER_H_

#include <memory>

#include "aav/scanner_interface.h"

namespace aav {
class DexSigMgr;

// IScanner for standalone DEX files. Init builds the DEX signature indexes once
// (shared via the Init context) and ScanTarget runs the parser over each DEX.
// Archives are handled by ApkScanner, so ScanStream is unsupported here.
class DexScanner : public IScanner {
 public:
  DexScanner();
  ~DexScanner();

  int Init(void* context);
  int Uninit();
  int ScanStream(IStream* stream, const ScanOption* option,
                 ScanResultPtr& result);
  int ScanTarget(ITarget* target, const ScanOption* option,
                 ScanResultPtr& result);
  int GetScannerId(ScannerId* id);

 private:
  std::unique_ptr<DexSigMgr> dex_sig_mgr_;
};

}  // namespace aav

#endif
