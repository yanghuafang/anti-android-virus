#include <cstddef>
#include <string>

#include "aav/engine_interface.h"  // public facade
#include "doctest.h"
#include "sigtool/sample_data.h"
#include "unit/test_support.h"

namespace sample = aav::sample;
using aav::EngineConfig;
using aav::IEngine;
using aav::MakeEngine;
using aav::ScanReport;

namespace {
struct Caught {
  int calls = 0;
  bool malware = false;
  bool has_path = false;
  bool has_code = false;
  std::string name;
};

void OnReport(const ScanReport* r, void* user) {
  Caught* c = static_cast<Caught*>(user);
  c->calls++;
  if (r->is_malware) {
    c->malware = true;
  }
  for (size_t i = 0; i < r->sig_count; ++i) {
    if (r->sig_ids[i] == sample::kPathSigId) {
      c->has_path = true;
    }
    if (r->sig_ids[i] == sample::kCodeSigId) {
      c->has_code = true;
    }
  }
  if (r->sig_count > 0 && r->names && r->names[0]) {
    c->name = r->names[0];
  }
}
}  // namespace

TEST_CASE("IEngine scans a DEX buffer and reports malware + name") {
  sample::Bytes sig = sample::BuildSampleSig();
  aav_test::TempFile tf =
      aav_test::MakeTempFile(".sig", sig.data(), sig.size());

  IEngine* eng = MakeEngine();
  REQUIRE(eng);
  EngineConfig cfg;
  const std::string path = tf.Str();
  REQUIRE(eng->Init(path.c_str(), &cfg) == 0);

  sample::Bytes dex = sample::BuildSampleDex();
  Caught c;
  CHECK(eng->ScanBuffer(dex.data(), dex.size(), "sample.dex", OnReport, &c) ==
        0);
  CHECK(c.calls == 1);
  CHECK(c.malware);
  CHECK(c.has_path);
  CHECK(c.has_code);
  CHECK(c.name == sample::kMalwareName);
  eng->Destroy();
}

#ifdef AAV_HAVE_MINIZ
TEST_CASE("IEngine scans an APK buffer (unpacks classes.dex)") {
  sample::Bytes sig = sample::BuildSampleSig();
  aav_test::TempFile tf =
      aav_test::MakeTempFile(".sig", sig.data(), sig.size());

  IEngine* eng = MakeEngine();
  REQUIRE(eng);
  EngineConfig cfg;
  const std::string path = tf.Str();
  REQUIRE(eng->Init(path.c_str(), &cfg) == 0);

  sample::Bytes apk = sample::BuildSampleApk(sample::BuildSampleDex());
  Caught c;
  CHECK(eng->ScanBuffer(apk.data(), apk.size(), "sample.apk", OnReport, &c) ==
        0);
  CHECK(c.malware);
  CHECK(c.has_path);
  CHECK(c.has_code);
  eng->Destroy();
}
#endif
