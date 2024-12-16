#include <string>
#include <vector>

#include "aav/sig_format.h"  // SigItem, SigFormat
#include "common_define.h"   // kAdSuccess
#include "doctest.h"
#include "sample_data.h"
#include "sig_mgr.h"
#include "test_support.h"

using namespace aav;

TEST_CASE("SigMgr loads a real DB and resolves malware names") {
  sample::Bytes sig = sample::BuildSampleSig();
  aav_test::TempFile tf =
      aav_test::MakeTempFile(".sig", sig.data(), sig.size());

  SigMgr mgr;
  const std::string path = tf.str();
  REQUIRE(mgr.LoadSigs(path.c_str(), nullptr) == kAdSuccess);
  CHECK(mgr.SigVersion() == 1);

  SigItem* item = nullptr;
  CHECK(mgr.GetData(kSigFormatDexPath, &item) == kAdSuccess);
  REQUIRE(item != nullptr);
  CHECK(item->buf_size > 0u);
  SigItem* missing = nullptr;
  CHECK(mgr.GetData(kSigFormatWhiteElf, &missing) != kAdSuccess);

  char name[128];
  CHECK(mgr.GetMalwareName(sample::kPathSigId, name, sizeof(name)) ==
        kAdSuccess);
  CHECK(std::string(name) == sample::kMalwareName);
  CHECK(mgr.GetMalwareName(sample::kCodeSigId, name, sizeof(name)) ==
        kAdSuccess);
  CHECK(std::string(name) == sample::kMalwareName);
}

TEST_CASE("SigMgr rejects a corrupt DB") {
  std::vector<uint8_t> junk(64, 0xEE);
  aav_test::TempFile tf =
      aav_test::MakeTempFile(".sig", junk.data(), junk.size());
  SigMgr mgr;
  const std::string path = tf.str();
  CHECK(mgr.LoadSigs(path.c_str(), nullptr) != kAdSuccess);
}

TEST_CASE("SigMgr fails to load a missing file") {
  SigMgr mgr;
  CHECK(mgr.LoadSigs("/no/such/aav-db.sig", nullptr) != kAdSuccess);
}
