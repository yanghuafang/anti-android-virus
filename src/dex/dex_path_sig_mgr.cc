#include "dex_path_sig_mgr.h"

#include <assert.h>
#include <string.h>

#include <memory>
#include <new>

#include "aav/sig_format.h"
#include "aav/sig_mgr_interface.h"
#include "ac_matcher.h"
#include "crc32.h"
#include "dex_sig.h"
#include "log.h"

namespace aav {

namespace {
// Alignment-safe little-endian reads from the packed signature-DB byte stream
// (member access via packed structs decays to aligned loads and trips UBSan).
inline uint16_t Rd16(const char* p) {
  uint16_t v;
  memcpy(&v, p, sizeof(v));
  return v;
}
inline uint32_t Rd32(const char* p) {
  uint32_t v;
  memcpy(&v, p, sizeof(v));
  return v;
}
}  // namespace

DexPathSigMgr::DexPathSigMgr() {}

DexPathSigMgr::~DexPathSigMgr() { Uninit(); }

int DexPathSigMgr::Init(ISigMgr* sig_mgr) {
  if (nullptr == sig_mgr) return -1;

  SigItem* path_sig = nullptr;
  if (0 != sig_mgr->GetData(kSigFormatDexPath, &path_sig)) {
    AAV_LOGE("DexPathSigMgr::Init GetData(kSigFormatDexPath) failed");
    return -1;
  }
  if (0 != ParsePathSig(path_sig)) {
    AAV_LOGE("DexPathSigMgr::Init ParsePathSig failed");
    return -1;
  }
  if (0 != CreateAcTree()) {
    AAV_LOGE("DexPathSigMgr::Init CreateAcTree failed");
    return -1;
  }
  return 0;
}

int DexPathSigMgr::Uninit() {
  ac_tree_.reset();
  path_sig_list_.clear();
  return 0;
}

int DexPathSigMgr::ParsePathSig(const SigItem* path_sig_item) {
  assert(nullptr != path_sig_item);
  assert(kSigFormatDexPath == path_sig_item->format);
  assert(nullptr != path_sig_item->buf);
  if (nullptr == path_sig_item) return -1;
  if (nullptr == path_sig_item->buf) return -1;

  int count = 0;
  char* cur = static_cast<char*>(path_sig_item->buf);
  DexPathSigRaw* sig = reinterpret_cast<DexPathSigRaw*>(cur);
  char* end = static_cast<char*>(path_sig_item->buf) + path_sig_item->buf_size;
  if (0 == path_sig_item->buf_size) {
    AAV_LOGD("DexPathSigMgr::ParsePathSig: empty path sig buffer");
    return 0;
  }

  try {
    while (true) {
      // DexPathSigRaw (packed): [sig_id:u32][str_match:u8][logic_match:u8]
      //                        [path_max_layer:u16][path_crcs: layer*u32]
      const char* p = reinterpret_cast<const char*>(sig);
      DexPathSig path_sig;

      path_sig.sig_id = Rd32(p);
      path_sig.str_match_type =
          static_cast<StrMatchType>(static_cast<uint8_t>(p[4]));
      assert(path_sig.str_match_type > kStrMatchTypeUnknown &&
             path_sig.str_match_type < kStrMatchTypeEndUnknown);
      if (path_sig.str_match_type <= kStrMatchTypeUnknown ||
          path_sig.str_match_type >= kStrMatchTypeEndUnknown)
        return -1;

      path_sig.logic_match_type =
          static_cast<LogicMatchType>(static_cast<uint8_t>(p[5]));
      assert(path_sig.logic_match_type > kLogicMatchTypeUnknown &&
             path_sig.logic_match_type < kLogicMatchTypeEndUnknown);
      if (path_sig.logic_match_type <= kLogicMatchTypeUnknown ||
          path_sig.logic_match_type >= kLogicMatchTypeEndUnknown)
        return -1;

      uint16_t path_max_layer = Rd16(p + 6);
      assert(path_max_layer > 0);
      path_sig.path_crcs.reserve(path_max_layer);
      for (int i = 0; i < path_max_layer; i++)
        path_sig.path_crcs.push_back(Rd32(p + 8 + i * sizeof(uint32_t)));

      path_sig_list_.push_back(path_sig);
      count++;

      cur += (sizeof(DexPathSigRaw) + (path_max_layer - 1) * sizeof(uint32_t));
      sig = reinterpret_cast<DexPathSigRaw*>(cur);
      if (cur >= end) break;
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexPathSigMgr::ParsePathSig bad_alloc: %s", e.what());
    return -1;
  }
  assert(count == path_sig_item->sig_count);

  return 0;
}

int DexPathSigMgr::CreateAcTree() {
  ac_tree_.reset(new (std::nothrow) ACTree);
  if (nullptr == ac_tree_) return -1;
  return ac_tree_->Build(path_sig_list_);
}

int DexPathSigMgr::SearchClassPath(const char* class_path,
                                   DexPathSig** path_sig) {
  assert(nullptr != class_path && nullptr != path_sig);
  if (nullptr == class_path || nullptr == path_sig) return -1;

  std::list<int> dot_indexes;
  int i = 0;
  int len = 0;
  try {
    while (class_path[i] != 0) {
      if ('.' == class_path[i]) dot_indexes.push_back(i);
      len++;
      i++;
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexPathSigMgr::SearchClassPath bad_alloc: %s", e.what());
    return -1;
  }

  std::vector<uint32_t> path_crcs;
  try {
    path_crcs.reserve(dot_indexes.size() + 1);

    const char* begin = class_path;
    int begin_index = 0;
    for (std::list<int>::iterator i = dot_indexes.begin();
         i != dot_indexes.end(); ++i) {
      if (*i > begin_index) {
        uint32_t crc;
        if (0 != CalcCrC32(begin, *i - begin_index, crc)) return -1;
        path_crcs.push_back(crc);
      }
      begin = &class_path[*i + 1];
      begin_index = *i + 1;
    }
    if (begin_index < len) {
      uint32_t crc;
      if (0 != CalcCrC32(begin, len - begin_index, crc)) return -1;
      path_crcs.push_back(crc);
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexPathSigMgr::SearchClassPath bad_alloc: %s", e.what());
    return -1;
  }

  return ac_tree_->Search(path_crcs, path_sig);
}

int DexPathSigMgr::CalcCrC32(const char* str, int len, uint32_t& crc) {
  if (nullptr == str || len < 0) return -1;
  crc = Crc32(0, str, static_cast<uint32_t>(len));
  return 0;
}

}  // namespace aav
