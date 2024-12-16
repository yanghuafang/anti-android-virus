#include <cstring>
#include <list>
#include <string>
#include <vector>

#include "ac_matcher.h"
#include "crc32.h"
#include "dex_path_sig_mgr.h"  // DexPathSig
#include "dex_sig.h"           // STR_MATCH_TYPE, LOGIC_MATCH_TYPE
#include "doctest.h"

using namespace aav;

static uint32_t C(const char* s) {
  return aav::Crc32(0, s, static_cast<uint32_t>(strlen(s)));
}

TEST_CASE("ACTree EQUAL match hits exact path and misses others") {
  std::list<DexPathSig> sigs;
  DexPathSig s;
  s.sig_id = 1001;
  s.str_match_type = kStrMatchTypeEqual;
  s.logic_match_type = kLogicMatchTypeOr;
  s.path_crcs = {C("com"), C("aav"), C("evil")};
  sigs.push_back(s);

  ACTree tree;
  REQUIRE(tree.Build(sigs) == 0);

  std::vector<uint32_t> path = {C("com"), C("aav"), C("evil")};
  DexPathSig* hit = nullptr;
  CHECK(tree.Search(path, &hit) == 0);
  REQUIRE(hit != nullptr);
  CHECK(hit->sig_id == 1001u);

  std::vector<uint32_t> other = {C("com"), C("aav"), C("good")};
  DexPathSig* miss = nullptr;
  CHECK(tree.Search(other, &miss) != 0);
}

TEST_CASE("ACTree START_WITH matches a prefix") {
  std::list<DexPathSig> sigs;
  DexPathSig s;
  s.sig_id = 2002;
  s.str_match_type = kStrMatchTypeStartWith;
  s.logic_match_type = kLogicMatchTypeOr;
  s.path_crcs = {C("com"), C("ads")};
  sigs.push_back(s);

  ACTree tree;
  REQUIRE(tree.Build(sigs) == 0);

  std::vector<uint32_t> path = {C("com"), C("ads"), C("banner")};
  DexPathSig* hit = nullptr;
  CHECK(tree.Search(path, &hit) == 0);
  REQUIRE(hit != nullptr);
  CHECK(hit->sig_id == 2002u);
}

// END_WITH matches when the signature's segments occur as a run that is *not*
// anchored at the path start -- Search reaches the terminal node via a failure
// link, so index+1 > layer in IsMatchAt. It therefore fires on com.ad.sdk but
// not on the exact path ad.sdk (that is an EQUAL match, not END_WITH).
TEST_CASE("ACTree END_WITH matches a non-anchored suffix") {
  std::list<DexPathSig> sigs;
  DexPathSig s;
  s.sig_id = 3003;
  s.str_match_type = kStrMatchTypeEndWith;
  s.logic_match_type = kLogicMatchTypeOr;
  s.path_crcs = {C("ad"), C("sdk")};
  sigs.push_back(s);

  ACTree tree;
  REQUIRE(tree.Build(sigs) == 0);

  std::vector<uint32_t> suffix = {C("com"), C("ad"), C("sdk")};
  DexPathSig* hit = nullptr;
  CHECK(tree.Search(suffix, &hit) == 0);
  REQUIRE(hit != nullptr);
  CHECK(hit->sig_id == 3003u);

  DexPathSig* miss = nullptr;
  std::vector<uint32_t> anchored = {C("ad"), C("sdk")};  // EQUAL, not END_WITH
  CHECK(tree.Search(anchored, &miss) != 0);
  std::vector<uint32_t> other = {C("com"), C("x"), C("y")};
  CHECK(tree.Search(other, &miss) != 0);
}

// CONTAIN matches wherever the signature's segments occur -- at the start, in
// the middle, or as the whole path.
TEST_CASE("ACTree CONTAIN matches anywhere in the path") {
  std::list<DexPathSig> sigs;
  DexPathSig s;
  s.sig_id = 4004;
  s.str_match_type = kStrMatchTypeContain;
  s.logic_match_type = kLogicMatchTypeOr;
  s.path_crcs = {C("core")};
  sigs.push_back(s);

  ACTree tree;
  REQUIRE(tree.Build(sigs) == 0);

  DexPathSig* hit = nullptr;
  std::vector<uint32_t> middle = {C("com"), C("core"), C("util")};
  CHECK(tree.Search(middle, &hit) == 0);
  REQUIRE(hit != nullptr);
  CHECK(hit->sig_id == 4004u);

  hit = nullptr;
  std::vector<uint32_t> only = {C("core")};
  CHECK(tree.Search(only, &hit) == 0);

  DexPathSig* miss = nullptr;
  std::vector<uint32_t> none = {C("com"), C("util")};
  CHECK(tree.Search(none, &miss) != 0);
}

// Regression test for the sorted-children binary search. Many signatures share
// the "com" prefix, so the "com" node ends up with many children inserted in
// signature order, which is NOT sorted by CRC value. Search binary-searches the
// children, so ProcessSig must keep them sorted on insert or lookups for the
// out-of-order children would silently miss. The single-child tests above never
// exercise this path.
TEST_CASE("ACTree binary-searches many (unsorted-insertion) children") {
  const char* segs[] = {"one",  "two", "three", "four",
                        "five", "six", "seven", "eight"};
  const int n = static_cast<int>(sizeof(segs) / sizeof(segs[0]));

  std::list<DexPathSig> sigs;
  for (int k = 0; k < n; ++k) {
    DexPathSig s;
    s.sig_id = static_cast<uint32_t>(100 + k);
    s.str_match_type = kStrMatchTypeEqual;
    s.logic_match_type = kLogicMatchTypeOr;
    s.path_crcs = {C("com"), C(segs[k])};
    sigs.push_back(s);
  }

  ACTree tree;
  REQUIRE(tree.Build(sigs) == 0);

  // Every signature must be found; an unsorted children vector would make the
  // binary search miss the ones whose CRC breaks the assumed ordering.
  for (int k = 0; k < n; ++k) {
    std::vector<uint32_t> path = {C("com"), C(segs[k])};
    DexPathSig* hit = nullptr;
    CHECK(tree.Search(path, &hit) == 0);
    REQUIRE(hit != nullptr);
    CHECK(hit->sig_id == static_cast<uint32_t>(100 + k));
  }
}
