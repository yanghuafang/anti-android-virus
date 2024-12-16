#include "dex_path_scan_result.h"
#include "dex_sig.h"
#include "doctest.h"

using namespace aav;

// Package-path decision logic (thesis 3.2.2): negation (NOT/XOR) outranks
// affirmation (OR/AND); a single XOR hit is positive, two is a veto.
TEST_CASE("OR hit => malware") {
  DexPathScanResult r;
  r.SetSigId(1);
  r.AddLogicMatchType(kLogicMatchTypeOr);
  CHECK(r.IsMalware());
}

TEST_CASE("NOT overrides a positive") {
  DexPathScanResult r;
  r.SetSigId(1);
  r.AddLogicMatchType(kLogicMatchTypeOr);
  r.AddLogicMatchType(kLogicMatchTypeNot);
  CHECK_FALSE(r.IsMalware());
}

TEST_CASE("AND requires more than one hit") {
  DexPathScanResult r;
  r.SetSigId(1);
  r.AddLogicMatchType(kLogicMatchTypeAnd);
  CHECK_FALSE(r.IsMalware());
  r.AddLogicMatchType(kLogicMatchTypeAnd);
  CHECK(r.IsMalware());
}

TEST_CASE("XOR: one hit positive, two hits veto") {
  DexPathScanResult r;
  r.SetSigId(1);
  r.AddLogicMatchType(kLogicMatchTypeXor);
  CHECK(r.IsMalware());
  r.AddLogicMatchType(kLogicMatchTypeXor);
  CHECK_FALSE(r.IsMalware());
}
