#ifndef AAV_DEX_DEX_PATH_SIG_MGR_H_
#define AAV_DEX_DEX_PATH_SIG_MGR_H_

#include <list>
#include <memory>
#include <string>
#include <vector>

#include "dex_sig.h"

namespace aav {

struct SigItem;

class ISigMgr;
class ACTree;

// One class-path signature: the CRC of each `.`-separated path segment, plus
// how to match the path (str_match_type: EQUAL/START_WITH/...) and how this hit
// combines with others for the same sig_id (logic_match_type: AND/OR/XOR/NOT).
struct DexPathSig {
  uint32_t sig_id;
  StrMatchType str_match_type;
  LogicMatchType logic_match_type;
  std::vector<uint32_t> path_crcs;
};

// Owns the class-path signatures parsed from the DB and the Aho-Corasick trie
// built from their segment CRCs. SearchClassPath returns the matching signature
// (if any) for a class path in a single trie walk.
class DexPathSigMgr {
 public:
  DexPathSigMgr();
  ~DexPathSigMgr();

  int Init(ISigMgr* sig_mgr);
  int Uninit();

  int SearchClassPath(const char* class_path, DexPathSig** path_sig);

 private:
  int ParsePathSig(const SigItem* path_sig_item);
  int CreateAcTree();
  int CalcCrC32(const char* str, int len, uint32_t& crc);

 private:
  std::list<DexPathSig> path_sig_list_;
  std::unique_ptr<ACTree> ac_tree_;
};

}  // namespace aav

#endif
