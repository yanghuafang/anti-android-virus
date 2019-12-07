#include "sigtool/sample_data.h"

// The APK scanner needs miniz (zip) support; without it there is nothing to
// test here.
#ifdef AAV_HAVE_MINIZ

#include <cstdint>
#include <string>

#include "aav/factory.h"
#include "aav/mem_source.h"
#include "aav/mem_stream_interface.h"
#include "aav/scan_option.h"
#include "aav/scan_result.h"
#include "aav/scanner_interface.h"
#include "aav/sig_mgr_interface.h"
#include "doctest.h"
#include "sig/common_define.h"  // kAdSuccess
#include "unit/test_support.h"

namespace sample = aav::sample;
using aav::IMemStream;
using aav::IScanner;
using aav::ISigMgr;
using aav::kAdSuccess;
using aav::MakeApkScanner;
using aav::MakeMemStream;
using aav::MakeSigMgr;
using aav::MemSource;
using aav::ObjPtr;
using aav::ScanOption;
using aav::ScanResultPtr;

TEST_CASE("ApkScanner detects malware in an in-memory APK") {
  sample::Bytes sig = sample::BuildSampleSig();
  aav_test::TempFile tf =
      aav_test::MakeTempFile(".sig", sig.data(), sig.size());

  ObjPtr<ISigMgr> sm = MakeSigMgr();
  REQUIRE(sm);
  const std::string path = tf.Str();
  REQUIRE(sm->LoadSigs(path.c_str(), nullptr) == kAdSuccess);

  ObjPtr<IScanner> apk = MakeApkScanner();
  REQUIRE(apk);
  REQUIRE(apk->Init(sm.get()) == 0);

  sample::Bytes apk_bytes = sample::BuildSampleApk(sample::BuildSampleDex());
  REQUIRE(!apk_bytes.empty());

  ObjPtr<IMemStream> stream = MakeMemStream();
  REQUIRE(stream);
  MemSource src{};
  src.mode = 0;
  src.name = "sample.apk";
  src.buf = apk_bytes.data();
  src.buf_size = static_cast<int32_t>(apk_bytes.size());
  REQUIRE(stream->Init(&src) == 0);

  ScanOption opt{};
  opt.config.dex = 1;  // the DEX scanner is gated on this flag
  opt.config.apk = 1;
  ScanResultPtr result;
  CHECK(apk->ScanStream(stream.get(), &opt, result) == 0);
  REQUIRE(result);
  CHECK(result->is_malware);

  bool has_path = false;
  bool has_code = false;
  for (uint16_t i = 0; i < result->sig_count; ++i) {
    if (result->sig_id[i] == sample::kPathSigId) {
      has_path = true;
    }
    if (result->sig_id[i] == sample::kCodeSigId) {
      has_code = true;
    }
  }
  CHECK(has_path);
  CHECK(has_code);
}

#endif  // AAV_HAVE_MINIZ
