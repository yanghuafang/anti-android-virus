#include "dex_scanner.h"

#include <stdio.h>
#include <stdlib.h>

#include <memory>
#include <new>
#include <vector>

#include "aav/scan_option.h"
#include "aav/scan_result.h"
#include "aav/scanner_interface.h"
#include "aav/sig_mgr_interface.h"
#include "dex_parser.h"
#include "dex_sig_mgr.h"
#include "malware_name.h"

namespace aav {

DexScanner::DexScanner() {}

DexScanner::~DexScanner() { Uninit(); }

int DexScanner::Init(void* context) {
  if (nullptr == context) return -1;

  ISigMgr* sig_mgr = static_cast<ISigMgr*>(context);
  dex_sig_mgr_.reset(new (std::nothrow) DexSigMgr);
  if (nullptr == dex_sig_mgr_) return -1;
  if (0 != dex_sig_mgr_->Init(sig_mgr)) return -1;
  return 0;
}

int DexScanner::Uninit() {
  dex_sig_mgr_.reset();
  return 0;
}

int DexScanner::ScanStream(IStream* stream, const ScanOption* option,
                           ScanResultPtr& result) {
  // A DEX is a leaf scan object -- an ITarget you scan directly (see
  // ScanTarget) -- not an IStream (an archive you extract entries from). So
  // scanning a DEX as a stream is unsupported, mirroring how the APK scanner
  // rejects a target (ApkScanner::ScanTarget).
  (void)stream;
  (void)option;
  result.reset();
  return -1;
}

int DexScanner::ScanTarget(ITarget* target, const ScanOption* option,
                           ScanResultPtr& result) {
  if (nullptr == target || nullptr == option) return -1;
  if (!option->config.dex) return -1;

  result.reset();

  std::unique_ptr<DexParser> dex_parser(new (std::nothrow) DexParser);
  if (nullptr == dex_parser) return -1;
  if (0 != dex_parser->Init(dex_sig_mgr_.get(), target)) return -1;

  std::vector<uint32_t> sig_id_array;
  if (0 != dex_parser->Scan(sig_id_array)) return -1;

  if (!sig_id_array.empty()) {
    int size =
        sizeof(ScanResult) + (sig_id_array.size() - 1) * sizeof(uint32_t);
    ScanResult* scan_result = static_cast<ScanResult*>(malloc(size));
    if (nullptr == scan_result) return -1;
    scan_result->is_white = 0;
    scan_result->is_malware = 1;
    scan_result->scanner_id = static_cast<uint16_t>(kScannerIdDex);
    scan_result->file_type = static_cast<uint16_t>(kMalwareFileFormatDex);
    scan_result->sig_count = sig_id_array.size();
    for (int i = 0; i < scan_result->sig_count; i++)
      scan_result->sig_id[i] = sig_id_array[i];
    result.reset(scan_result);
  } else {
    ScanResult* scan_result =
        static_cast<ScanResult*>(malloc(sizeof(ScanResult)));
    if (nullptr == scan_result) return -1;
    scan_result->is_white = 0;
    scan_result->is_malware = 0;
    scan_result->scanner_id = static_cast<uint16_t>(kScannerIdDex);
    scan_result->file_type = static_cast<uint16_t>(kMalwareFileFormatDex);
    scan_result->sig_count = 0;
    scan_result->sig_id[0] = 0;
    result.reset(scan_result);
  }

  return 0;
}

int DexScanner::GetScannerId(ScannerId* id) {
  if (nullptr == id) return -1;

  *id = kScannerIdDex;
  return 0;
}

}  // namespace aav
