#include <cstddef>
#include <string>

#include "aav/engine_interface.h"  // public facade
#include "doctest.h"
#include "sample_data.h"
#include "test_support.h"

using namespace aav;

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
  if (r->is_malware) c->malware = true;
  for (size_t i = 0; i < r->sig_count; ++i) {
    if (r->sig_ids[i] == sample::kPathSigId) c->has_path = true;
    if (r->sig_ids[i] == sample::kCodeSigId) c->has_code = true;
  }
  if (r->sig_count > 0 && r->names && r->names[0]) c->name = r->names[0];
}
}  // namespace

TEST_CASE("IEngine scans a DEX buffer and reports malware + name") {
  sample::Bytes sig = sample::BuildSampleSig();
  aav_test::TempFile tf =
      aav_test::MakeTempFile(".sig", sig.data(), sig.size());

  IEngine* eng = MakeEngine();
  REQUIRE(eng);
  EngineConfig cfg;
  const std::string path = tf.str();
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

// Exercises the hierarchical --analysis report end to end on the sample DEX:
// two classes, Worker's static + instance fields, its direct work() and its
// virtual run(I)V (with one parameter).
TEST_CASE("IEngine --analysis reports classes, fields, and method protos") {
  sample::Bytes sig = sample::BuildSampleSig();
  aav_test::TempFile tf =
      aav_test::MakeTempFile(".sig", sig.data(), sig.size());

  IEngine* eng = MakeEngine();
  REQUIRE(eng);
  EngineConfig cfg;
  cfg.analysis = 1;
  const std::string path = tf.str();
  REQUIRE(eng->Init(path.c_str(), &cfg) == 0);

  struct Analysis {
    size_t class_count = 0;
    bool static_field = false;
    bool instance_field = false;
    bool direct_work = false;
    bool virtual_run_with_param = false;
  } a;

  auto cb = [](const ScanReport* r, void* user) {
    Analysis* out = static_cast<Analysis*>(user);
    out->class_count = r->class_count;
    for (size_t i = 0; i < r->class_count; ++i) {
      const ClassFeature& c = r->classes[i];
      for (size_t f = 0; f < c.field_count; ++f)
        (c.fields[f].is_static ? out->static_field : out->instance_field) =
            true;
      for (size_t m = 0; m < c.method_count; ++m) {
        const MethodFeature& mf = c.methods[m];
        const std::string name = mf.method_name ? mf.method_name : "";
        if (name == "work" && mf.is_direct) out->direct_work = true;
        if (name == "run" && !mf.is_direct && mf.param_count == 1)
          out->virtual_run_with_param = true;
      }
    }
  };

  sample::Bytes dex = sample::BuildSampleDex();
  CHECK(eng->ScanBuffer(dex.data(), dex.size(), "sample.dex", cb, &a) == 0);
  CHECK(a.class_count == 2);
  CHECK(a.static_field);
  CHECK(a.instance_field);
  CHECK(a.direct_work);
  CHECK(a.virtual_run_with_param);
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
  const std::string path = tf.str();
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
