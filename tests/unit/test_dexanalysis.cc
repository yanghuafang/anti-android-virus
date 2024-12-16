#include "dex_analysis.h"
#include "doctest.h"

using namespace aav;

TEST_CASE("Dex analysis toggle and report round-trip") {
  const bool prev = IsDexAnalysisEnabled();

  SetDexAnalysisEnabled(false);
  CHECK_FALSE(IsDexAnalysisEnabled());
  SetDexAnalysisEnabled(true);
  CHECK(IsDexAnalysisEnabled());

  MutableDexAnalysisReport().classes.clear();
  DexAnalysisClass c;
  c.class_path = "com.example.evil";
  c.super_class = "Landroid/app/Activity;";
  DexAnalysisMethod m;
  m.method_name = "onCreate";
  m.return_type = "V";
  m.params.push_back("Landroid/os/Bundle;");
  c.methods.push_back(m);
  MutableDexAnalysisReport().classes.push_back(c);

  const DexAnalysisReport& r = GetDexAnalysisReport();
  REQUIRE(r.classes.size() == 1);
  CHECK(r.classes[0].class_path == "com.example.evil");
  REQUIRE(r.classes[0].methods.size() == 1);
  CHECK(r.classes[0].methods[0].method_name == "onCreate");
  CHECK(r.classes[0].methods[0].params.size() == 1);

  SetDexAnalysisEnabled(prev);
}
