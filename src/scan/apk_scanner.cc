#include "apk_scanner.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "aav/factory.h"
#include "aav/mem_source.h"
#include "aav/mem_target_interface.h"
#include "aav/scan_option.h"
#include "aav/scan_result.h"
#include "aav/stream_interface.h"
#include "log.h"
#include "malware_name.h"

#ifdef AAV_HAVE_MINIZ
#include "miniz.h"

namespace aav {
#endif

ApkScanner::ApkScanner() {}

ApkScanner::~ApkScanner() { Uninit(); }

int ApkScanner::Init(void* context) {
  if (nullptr == context) return -1;
  // The APK scanner detects malware in an app's classes.dex, so it drives a DEX
  // scanner that shares the same signature manager (the Init context).
  dex_scanner_ = MakeDexScanner();
  if (!dex_scanner_ || 0 != dex_scanner_->Init(context)) {
    dex_scanner_.reset();
    return -1;
  }
  return 0;
}

int ApkScanner::Uninit() {
  dex_scanner_.reset();
  return 0;
}

int ApkScanner::ScanApkBytes(const void* data, size_t size,
                             const ScanOption* option, ScanResultPtr& result) {
  result.reset();
  if (nullptr == data || 0 == size || !dex_scanner_) return -1;

#ifdef AAV_HAVE_MINIZ
  mz_zip_archive zip;
  memset(&zip, 0, sizeof(zip));
  if (!mz_zip_reader_init_mem(&zip, data, size, 0)) {
    AAV_LOGE("ApkScanner: not a valid zip/apk image");
    return -1;
  }

  // Modern apps are multidex: classes.dex, classes2.dex, classes3.dex, ...
  // (numbered contiguously, no gaps). Scan each present member and merge the
  // hits into a single result.
  std::vector<uint32_t> sig_ids;
  bool any_dex = false;
  bool is_malware = false;
  bool is_white = false;
  for (int i = 1;; ++i) {
    char entry[32];
    if (1 == i)
      snprintf(entry, sizeof(entry), "classes.dex");
    else
      snprintf(entry, sizeof(entry), "classes%d.dex", i);

    int index = mz_zip_reader_locate_file(&zip, entry, nullptr, 0);
    if (index < 0) break;  // no more multidex members

    size_t dex_size = 0;
    void* p = mz_zip_reader_extract_to_heap(&zip, static_cast<mz_uint>(index),
                                            &dex_size, 0);
    if (nullptr == p) continue;
    std::string dex(static_cast<char*>(p), dex_size);
    mz_free(p);
    any_dex = true;

    MemSource source{};
    source.mode = 0;  // O_RDONLY
    source.name = entry;
    source.buf = &dex[0];
    source.buf_size = static_cast<int32_t>(dex.size());

    ObjPtr<IMemTarget> target = MakeMemtarget();
    if (!target || 0 != target->Init(&source)) continue;

    ScanResultPtr one;
    if (0 != dex_scanner_->ScanTarget(target.get(), option, one) || !one)
      continue;
    if (one->is_white) is_white = true;
    if (one->is_malware) {
      is_malware = true;
      for (uint16_t k = 0; k < one->sig_count; ++k)
        sig_ids.push_back(one->sig_id[k]);
    }
  }
  mz_zip_reader_end(&zip);

  if (!any_dex) {
    AAV_LOGE("ApkScanner: classes.dex not found in apk");
    return -1;
  }

  // Assemble the merged result with the same malloc + flexible-array layout the
  // DEX scanner uses (freed via aav::ScanResultFree).
  const size_t n = sig_ids.size();
  const size_t bytes = n > 0 ? sizeof(ScanResult) + (n - 1) * sizeof(uint32_t)
                             : sizeof(ScanResult);
  ScanResult* merged = static_cast<ScanResult*>(malloc(bytes));
  if (nullptr == merged) return -1;
  merged->is_white = is_white ? 1 : 0;
  merged->is_malware = is_malware ? 1 : 0;
  merged->scanner_id = static_cast<uint16_t>(kScannerIdApk);
  merged->file_type = static_cast<uint16_t>(kMalwareFileFormatDex);
  merged->sig_count = static_cast<uint16_t>(n);
  if (0 == n) merged->sig_id[0] = 0;
  for (size_t k = 0; k < n; ++k) merged->sig_id[k] = sig_ids[k];
  result.reset(merged);
  return 0;
#else
  (void)option;
  AAV_LOGE("ApkScanner: APK support not built (miniz disabled)");
  return -1;
#endif
}

int ApkScanner::ScanStream(IStream* stream, const ScanOption* option,
                           ScanResultPtr& result) {
  if (nullptr == stream || nullptr == option) return -1;
  result.reset();

  // Fast path: scan directly from the stream's contiguous view with no copy --
  // MemStream hands back its buffer, FileStream memory-maps the file.
  const void* view = nullptr;
  int64_t view_size = 0;
  if (0 == stream->GetView(&view, &view_size) && nullptr != view &&
      view_size > 0) {
    return ScanApkBytes(view, static_cast<size_t>(view_size), option, result);
  }

  // Fallback (streams without a view): materialize the archive by reading it.
  int64_t size = 0;
  if (0 != stream->GetSize(&size) || size <= 0) return -1;
  std::string buf;
  buf.resize(static_cast<size_t>(size));
  if (0 != stream->Seek(0, 0)) return -1;  // SEEK_SET
  int64_t total = 0;
  while (total < size) {
    int want = static_cast<int>(size - total);
    int got = 0;
    if (0 != stream->Read(&buf[total], want, &got) || got <= 0) return -1;
    total += got;
  }

  return ScanApkBytes(buf.data(), buf.size(), option, result);
}

int ApkScanner::ScanTarget(ITarget* target, const ScanOption* option,
                           ScanResultPtr& result) {
  // An APK is an archive -- an IStream you extract entries from (see
  // ScanStream) -- not an ITarget (a leaf scan object such as a DEX/ELF). So
  // scanning an APK as a target is unsupported, mirroring how the DEX scanner
  // rejects a stream (DexScanner::ScanStream).
  (void)target;
  (void)option;
  result.reset();
  return -1;
}

int ApkScanner::GetScannerId(ScannerId* id) {
  if (nullptr == id) return -1;
  *id = kScannerIdApk;
  return 0;
}

}  // namespace aav
