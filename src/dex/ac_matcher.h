#ifndef AAV_DEX_AC_MATCHER_H_
#define AAV_DEX_AC_MATCHER_H_

#include <stdint.h>

#include <list>
#include <memory>
#include <vector>

#include "dex_path_sig_mgr.h"

namespace aav {

// A node in the Aho-Corasick trie. Each node stands for one path segment (a
// class-path component identified by its CRC). Children are owned and kept
// sorted by `value`, which serves as both the ownership structure (destroying a
// node frees its whole subtree) and the lookup index Search binary-searches --
// there is no separate sibling list.
struct ACNode {
  uint32_t layer =
      0;  // depth from root: 0 at the root, 1 for the first segment
  uint32_t value = 0;         // CRC of this segment (unused at the root)
  ACNode* parent = nullptr;   // non-owning back-pointer; null at the root
  ACNode* failure = nullptr;  // Aho-Corasick failure link; non-owning
  DexPathSig* sig =
      nullptr;  // non-owning; set iff a signature ends at this node
  std::vector<std::unique_ptr<ACNode>> children;  // owning, sorted by value
};

class ACTree {
 public:
  ACTree();
  ~ACTree();

  int Build(std::list<DexPathSig>& path_sigs);
  int Search(const std::vector<uint32_t>& path, DexPathSig** sig);

 private:
  int Clear();
  int CreateRoot();
  int CreateTrieTree(std::list<DexPathSig>& path_sigs);
  int ProcessSig(DexPathSig& sig);
  int LinkFailure(ACNode* node);
  int LinkFailureNode(ACNode* node);
  int GetSuffixPath(ACNode* node, std::list<uint32_t>& suffix_path);
  int SearchPrefixPath(std::list<uint32_t>& suffix_path, ACNode** failure_node);
  // Binary-search `node`'s sorted children for `value`; nullptr if absent.
  ACNode* FindChild(ACNode* node, uint32_t value);
  // Records a match at `cur` into `*sig` (when `cur` terminates a signature
  // that matches the path at position `index`) and returns true if the search
  // can stop (a full match at a leaf).
  bool TryMatch(ACNode* cur, size_t path_size, uint32_t index,
                DexPathSig** sig);
  // Whether a signature ending at `layer` matches a path of `path_size`
  // segments at position `index`, given its string-match mode.
  bool IsMatchAt(size_t path_size, uint32_t index, uint32_t layer,
                 StrMatchType match_type);

  std::unique_ptr<ACNode> root_;
};

}  // namespace aav

#endif
