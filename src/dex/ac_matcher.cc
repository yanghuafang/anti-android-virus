#include "ac_matcher.h"

#include <assert.h>

#include <algorithm>
#include <memory>
#include <new>
#include <utility>

#include "log.h"

namespace aav {

ACTree::ACTree() = default;

// root_ (a unique_ptr) owns the whole trie, so the default destructor frees it.
// Destruction recurses only on depth (each node destroys its children vector),
// which is bounded by the path length, so a wide DB cannot overflow the stack.
ACTree::~ACTree() = default;

int ACTree::Build(std::list<DexPathSig>& path_sigs) {
  if (0 != CreateRoot() || 0 != CreateTrieTree(path_sigs) ||
      0 != LinkFailure(root_.get())) {
    Clear();
    return -1;
  }
  return 0;
}

int ACTree::Clear() {
  root_.reset();
  return 0;
}

// Aho-Corasick walk over one class path (a sequence of segment CRCs). Follow
// child edges while they match; on a miss, jump along the failure link to the
// longest proper suffix still present in the trie, without rewinding the input.
// When a failure link lands back on the root the current segment has nowhere to
// go, so we must advance the input (i++) or the walk would stall. Returns 0 and
// sets *sig on the first terminal match.
int ACTree::Search(const std::vector<uint32_t>& path, DexPathSig** sig) {
  if (nullptr == sig) return -1;
  if (nullptr == root_ || root_->children.empty()) return -1;

  ACNode* root = root_.get();
  ACNode* cur = root;
  uint32_t i = 0;
  while (i < path.size()) {
    if (cur->children.empty()) {
      // Leaf: try to match here, then follow the failure link.
      if (TryMatch(cur, path.size(), i, sig)) return 0;
      cur = cur->failure;
      if (root == cur) i++;
      continue;
    }

    ACNode* child = FindChild(cur, path[i]);
    if (nullptr != child) {
      cur = child;
      if (TryMatch(cur, path.size(), i, sig)) return 0;
      i++;
    } else {
      cur = cur->failure;
      if (root == cur) i++;
    }
  }
  return -1;
}

ACNode* ACTree::FindChild(ACNode* node, uint32_t value) {
  auto it =
      std::lower_bound(node->children.begin(), node->children.end(), value,
                       [](const std::unique_ptr<ACNode>& c, uint32_t v) {
                         return c->value < v;
                       });
  if (it != node->children.end() && (*it)->value == value) return it->get();
  return nullptr;
}

bool ACTree::TryMatch(ACNode* cur, size_t path_size, uint32_t index,
                      DexPathSig** sig) {
  if (nullptr == cur->sig) return false;
  if (!IsMatchAt(path_size, index, cur->layer, cur->sig->str_match_type)) {
    return false;
  }
  *sig = cur->sig;
  AAV_LOGD("ACTree matched sig_id=%u layer=%u", cur->sig->sig_id, cur->layer);
  // A non-leaf may still terminate a longer signature deeper in the trie, so
  // keep walking unless this is a leaf.
  return cur->children.empty();
}

int ACTree::CreateRoot() {
  root_.reset(new (std::nothrow) ACNode);
  if (nullptr == root_) return -1;
  return 0;
}

int ACTree::CreateTrieTree(std::list<DexPathSig>& path_sigs) {
  for (std::list<DexPathSig>::iterator i = path_sigs.begin();
       i != path_sigs.end(); ++i) {
    if (0 != ProcessSig(*i)) return -1;
  }
  return 0;
}

int ACTree::ProcessSig(DexPathSig& sig) {
  assert(sig.path_crcs.size() > 0);
  assert(root_ != nullptr);
  ACNode* cur = root_.get();
  for (uint32_t i = 0; i < sig.path_crcs.size(); i++) {
    uint32_t crc = sig.path_crcs[i];
    bool last = (sig.path_crcs.size() - 1 == i);

    ACNode* child = FindChild(cur, crc);
    if (nullptr != child) {
      if (last) {
        if (nullptr != child->sig) {
          AAV_LOGE("ACTree: duplicate path signature (sig_id=%u); keeping last",
                   sig.sig_id);
        }
        child->sig = &sig;
      }
      cur = child;
      continue;
    }

    std::unique_ptr<ACNode> node(new (std::nothrow) ACNode);
    if (nullptr == node) return -1;
    node->layer = i + 1;
    node->parent = cur;
    node->value = crc;
    if (last) node->sig = &sig;
    assert(cur->layer + 1 == node->layer);

    // Insert into the child vector keeping it sorted by value so Search (and
    // subsequent FindChild lookups) can binary-search it.
    auto pos = std::lower_bound(cur->children.begin(), cur->children.end(), crc,
                                [](const std::unique_ptr<ACNode>& c,
                                   uint32_t v) { return c->value < v; });
    ACNode* raw = node.get();
    try {
      cur->children.insert(pos, std::move(node));
    } catch (std::bad_alloc& e) {
      AAV_LOGE("ACTree::ProcessSig bad_alloc: %s", e.what());
      return -1;
    }
    cur = raw;
  }
  return 0;
}

int ACTree::LinkFailure(ACNode* node) {
  // Compute this node's failure link, then recurse into its children. Recursion
  // depth is bounded by the path length; each node's link is computed
  // independently (LinkFailureNode re-searches the trie), so order is free.
  if (0 != LinkFailureNode(node)) return -1;
  for (auto& child : node->children) {
    if (0 != LinkFailure(child.get())) return -1;
  }
  return 0;
}

int ACTree::LinkFailureNode(ACNode* node) {
  if (nullptr == node) return 0;
  ACNode* root = root_.get();
  if (node == root) {
    node->failure = node;
    return 0;
  }

  if (root == node->parent) {
    node->failure = root;
    return 0;
  }

  std::list<uint32_t> suffix_path;
  if (0 != GetSuffixPath(node, suffix_path)) return -1;

  while (!suffix_path.empty()) {
    ACNode* failure_node = nullptr;
    if (0 == SearchPrefixPath(suffix_path, &failure_node)) {
      node->failure = failure_node;
      break;
    }
    suffix_path.erase(suffix_path.begin());
  }
  if (suffix_path.empty()) node->failure = root;

  return 0;
}

int ACTree::GetSuffixPath(ACNode* node, std::list<uint32_t>& suffix_path) {
  ACNode* cur = node;
  try {
    while (nullptr != cur && cur->layer > 1) {
      suffix_path.push_front(cur->value);
      cur = cur->parent;
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("ACTree::LinkFailureNode bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

int ACTree::SearchPrefixPath(std::list<uint32_t>& suffix_path,
                             ACNode** failure_node) {
  if (nullptr == root_) return -1;
  ACNode* cur = root_.get();
  for (std::list<uint32_t>::iterator i = suffix_path.begin();
       i != suffix_path.end(); ++i) {
    ACNode* child = FindChild(cur, *i);
    if (nullptr == child) return -1;
    *failure_node = child;
    cur = child;
  }
  return 0;
}

// Decide whether a signature that terminates at trie depth `layer` matches the
// path, given how far it has been consumed. `index` is the 0-based position of
// the segment just matched (so index + 1 segments are consumed), and `layer` is
// the signature's segment count.
//   index + 1 == layer : the signature is anchored at the path start ->
//       an exact match when it also spans the whole path (layer == path_size),
//       otherwise a "starts with" match.
//   index + 1 >  layer : we arrived here via a failure link, so the signature
//       matched a suffix of the consumed path -> "ends with".
// A "contains" signature matches wherever in the path it terminates.
bool ACTree::IsMatchAt(size_t path_size, uint32_t index, uint32_t layer,
                       StrMatchType match_type) {
  if (index + 1 == layer) {
    if (layer == path_size && kStrMatchTypeEqual == match_type) return true;
    if (layer < path_size && kStrMatchTypeStartWith == match_type) return true;
  } else if (index + 1 > layer) {
    if (layer < path_size && kStrMatchTypeEndWith == match_type) return true;
  } else {
    assert(false);
  }

  if (kStrMatchTypeContain == match_type) return true;
  return false;
}

}  // namespace aav
