#include <string.h>

#include <atomic>
#include <filesystem>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <vector>

#include "aav/engine_interface.h"
#include "aav/factory.h"
#include "aav/file_id_interface.h"
#include "aav/file_source.h"
#include "aav/file_stream_interface.h"
#include "aav/file_target_interface.h"
#include "aav/load_config.h"
#include "aav/mem_source.h"
#include "aav/mem_stream_interface.h"
#include "aav/mem_target_interface.h"
#include "aav/object_ptr.h"  // internal RAII for the object factories
#include "aav/scan_option.h"
#include "aav/scan_result.h"
#include "aav/scanner_interface.h"
#include "aav/sig_mgr_interface.h"
#include "dex_analysis.h"  // internal: --analysis toggle
#include "log.h"           // internal: runtime log level

namespace aav {
namespace {

const char* BaseName(const char* path) {
  const char* slash = strrchr(path, '/');
  return slash ? slash + 1 : path;
}

bool EndsWith(const std::string& s, const char* suffix) {
  size_t n = strlen(suffix);
  return s.size() >= n && 0 == s.compare(s.size() - n, n, suffix);
}

// A self-contained set of scanners sharing the engine's immutable signature
// manager. A single-threaded scan uses the engine's own members; a
// multi-threaded directory scan gives each worker its own set so all per-scan
// state stays thread-local (only sig_mgr_ is shared, and only read).
struct ScannerSet {
  ObjPtr<IFileID> file_id;
  ObjPtr<IScanner> apk_scanner;
  ObjPtr<IScanner> dex_scanner;
};

class Engine : public IEngine {
 public:
  int Init(const char* sig_db_path, const EngineConfig* config) override;
  int Scan(const char* path, ScanCallback cb, void* user_data) override;
  int ScanBuffer(const void* data, size_t size, const char* name,
                 ScanCallback cb, void* user_data) override;

 private:
  // Scan one file with the supplied scanners (the engine's own, or a worker's).
  int ScanFile(IFileID* file_id, IScanner* apk_scanner, IScanner* dex_scanner,
               const char* path, ScanCallback cb, void* user_data);
  int ScanOne(const char* path, ScanCallback cb, void* user_data);
  void ScanDir(const char* dir, ScanCallback cb, void* user_data);
  // Multi-threaded directory scan: collect targets, then scan them across
  // `threads` workers, each with its own ScannerSet.
  void ScanDirMt(const char* dir, ScanCallback cb, void* user_data,
                 int threads);
  // Recursively gather the .apk/.dex files under `dir` (honoring config_).
  void CollectTargets(const char* dir, std::vector<std::string>* out);
  // Create a fresh scanner set bound to the shared signature manager.
  bool BuildScannerSet(ScannerSet* set);
  // Build a POD ScanReport (backed by engine-owned storage valid only for the
  // duration of the call) and hand it to the callback. Serialized across scan
  // threads so the user callback is never invoked concurrently.
  void Emit(const char* path, const ScanResult* result, ScanCallback cb,
            void* user_data);

  ObjPtr<IFileID> file_id_;
  ObjPtr<ISigMgr> sig_mgr_;
  ObjPtr<IScanner> apk_scanner_;
  ObjPtr<IScanner> dex_scanner_;
  ScanOption scan_option_{};
  EngineConfig config_{};
  std::mutex emit_mutex_;  // serializes Emit() across scan threads
};

int Engine::Init(const char* sig_db_path, const EngineConfig* config) {
  if (nullptr == sig_db_path) return -1;
  if (config) config_ = *config;  // otherwise keep the defaults
  SetLogLevel(config_.verbose ? kLogDebug : kLogError);
  SetDexAnalysisEnabled(config_.analysis != 0);

  file_id_ = MakeFileid();
  if (!file_id_) return -1;

  sig_mgr_ = MakeSigmgr();
  if (!sig_mgr_ || 0 != sig_mgr_->Init(nullptr)) return -1;
  LoadFormatConfig lfc{};
  lfc.ad = 1;
  lfc.apk = config_.scan_apk ? 1 : 0;
  lfc.dex = config_.scan_dex ? 1 : 0;
  lfc.elf = 0;
  lfc.oat = 0;
  lfc.white = 1;
  lfc.heur = 0;
  lfc.analyzer = 0;
  if (0 != sig_mgr_->LoadSigs(sig_db_path, &lfc)) return -1;

  apk_scanner_ = MakeApkScanner();
  if (!apk_scanner_ || 0 != apk_scanner_->Init(sig_mgr_.get())) return -1;
  dex_scanner_ = MakeDexScanner();
  if (!dex_scanner_ || 0 != dex_scanner_->Init(sig_mgr_.get())) return -1;

  scan_option_.config.unarch = 1;
  scan_option_.config.unpack = 0;
  scan_option_.config.apk = config_.scan_apk ? 1 : 0;
  scan_option_.config.dex = config_.scan_dex ? 1 : 0;
  scan_option_.config.elf = 0;
  scan_option_.config.oat = 0;
  return 0;
}

int Engine::Scan(const char* path, ScanCallback cb, void* user_data) {
  if (nullptr == path || nullptr == cb || !sig_mgr_) return -1;
  std::error_code ec;
  if (std::filesystem::is_directory(path, ec)) {
    if (config_.scan_threads > 1)
      ScanDirMt(path, cb, user_data, config_.scan_threads);
    else
      ScanDir(path, cb, user_data);
    return 0;
  }
  return ScanOne(path, cb, user_data);
}

void Engine::ScanDir(const char* dir, ScanCallback cb, void* user_data) {
  std::error_code ec;
  std::filesystem::directory_iterator it(dir, ec);
  const std::filesystem::directory_iterator end;
  if (ec) return;
  for (; it != end; it.increment(ec)) {
    if (ec) break;
    const std::string child = it->path().string();
    const std::string name = it->path().filename().string();
    if ((config_.scan_apk && EndsWith(name, ".apk")) ||
        (config_.scan_dex && EndsWith(name, ".dex"))) {
      ScanOne(child.c_str(), cb, user_data);
    } else if (config_.recurse_dirs && it->is_directory(ec)) {
      ScanDir(child.c_str(), cb, user_data);
    }
  }
}

void Engine::CollectTargets(const char* dir, std::vector<std::string>* out) {
  std::error_code ec;
  std::filesystem::directory_iterator it(dir, ec);
  const std::filesystem::directory_iterator end;
  if (ec) return;
  for (; it != end; it.increment(ec)) {
    if (ec) break;
    const std::string child = it->path().string();
    const std::string name = it->path().filename().string();
    if ((config_.scan_apk && EndsWith(name, ".apk")) ||
        (config_.scan_dex && EndsWith(name, ".dex"))) {
      out->push_back(child);
    } else if (config_.recurse_dirs && it->is_directory(ec)) {
      CollectTargets(child.c_str(), out);
    }
  }
}

bool Engine::BuildScannerSet(ScannerSet* set) {
  set->file_id = MakeFileid();
  if (!set->file_id) return false;
  set->apk_scanner = MakeApkScanner();
  if (!set->apk_scanner || 0 != set->apk_scanner->Init(sig_mgr_.get()))
    return false;
  set->dex_scanner = MakeDexScanner();
  if (!set->dex_scanner || 0 != set->dex_scanner->Init(sig_mgr_.get()))
    return false;
  return true;
}

void Engine::ScanDirMt(const char* dir, ScanCallback cb, void* user_data,
                       int threads) {
  std::vector<std::string> targets;
  CollectTargets(dir, &targets);
  if (targets.empty()) return;

  // Never spawn more workers than there are files to scan.
  int nworkers = threads;
  if (nworkers > static_cast<int>(targets.size()))
    nworkers = static_cast<int>(targets.size());
  if (nworkers <= 1) {
    for (const std::string& p : targets) ScanOne(p.c_str(), cb, user_data);
    return;
  }

  // One scanner set per worker, built serially up front so that signature
  // manager access during setup is not itself concurrent. During the scan the
  // only shared state is the read-only signature manager.
  std::vector<ScannerSet> sets(nworkers);
  for (int i = 0; i < nworkers; i++) {
    if (!BuildScannerSet(&sets[i])) {
      AAV_LOGE("engine: failed to set up scan thread %d; scanning serially", i);
      for (const std::string& p : targets) ScanOne(p.c_str(), cb, user_data);
      return;
    }
  }

  // Workers pull file indices off a shared counter (dynamic load balancing --
  // scan cost per file varies widely).
  std::atomic<size_t> next{0};
  auto worker = [&](int idx) {
    const ScannerSet& s = sets[idx];
    for (;;) {
      const size_t i = next.fetch_add(1, std::memory_order_relaxed);
      if (i >= targets.size()) break;
      ScanFile(s.file_id.get(), s.apk_scanner.get(), s.dex_scanner.get(),
               targets[i].c_str(), cb, user_data);
    }
  };

  std::vector<std::thread> pool;
  pool.reserve(nworkers);
  for (int i = 0; i < nworkers; i++) pool.emplace_back(worker, i);
  for (std::thread& t : pool) t.join();
}

void Engine::Emit(const char* path, const ScanResult* result, ScanCallback cb,
                  void* user_data) {
  // Serialize so the user callback is never invoked concurrently, and so the
  // shared signature-manager name lookups below run one at a time.
  std::lock_guard<std::mutex> lock(emit_mutex_);
  // Storage that backs the POD ScanReport; alive until cb returns.
  std::vector<uint32_t> ids;
  std::vector<std::string> name_storage;
  std::vector<const char*> name_ptrs;
  // Backing storage for the hierarchical analysis view. Each is reserved to its
  // exact total below so it never reallocates -- the interior ClassFeature /
  // MethodFeature pointers into these arrays stay valid until cb returns.
  std::vector<ClassFeature> class_feats;
  std::vector<FieldFeature> field_feats;
  std::vector<MethodFeature> method_feats;
  std::vector<const char*> ptr_pool;

  ScanReport report;
  memset(&report, 0, sizeof(report));
  report.path = path;

  if (result) {
    report.is_white = result->is_white ? 1 : 0;
    report.is_malware = result->is_malware ? 1 : 0;
    ids.reserve(result->sig_count);
    name_storage.reserve(result->sig_count);
    for (int i = 0; i < result->sig_count; i++) {
      ids.push_back(result->sig_id[i]);
      char buf[64];
      if (0 == sig_mgr_->GetMalwareName(static_cast<int>(result->sig_id[i]),
                                        buf, sizeof(buf)))
        name_storage.emplace_back(buf);
      else
        name_storage.emplace_back();
    }
    name_ptrs.reserve(name_storage.size());
    for (const std::string& s : name_storage) name_ptrs.push_back(s.c_str());
    report.sig_ids = ids.empty() ? nullptr : ids.data();
    report.names = name_ptrs.empty() ? nullptr : name_ptrs.data();
    report.sig_count = ids.size();
  }

  if (config_.analysis) {
    const DexAnalysisReport& analysis = GetDexAnalysisReport();

    // Pre-count so every backing vector is reserved exactly once; without this
    // a realloc would dangle the interior pointers handed out below.
    size_t total_fields = 0, total_methods = 0, total_ptrs = 0;
    for (const DexAnalysisClass& c : analysis.classes) {
      total_fields += c.fields.size();
      total_methods += c.methods.size();
      for (const DexAnalysisMethod& m : c.methods)
        total_ptrs += m.params.size() + m.strings.size();
    }
    class_feats.reserve(analysis.classes.size());
    field_feats.reserve(total_fields);
    method_feats.reserve(total_methods);
    ptr_pool.reserve(total_ptrs);

    for (const DexAnalysisClass& c : analysis.classes) {
      const size_t field_begin = field_feats.size();
      for (const DexAnalysisField& fld : c.fields) {
        FieldFeature ff;
        memset(&ff, 0, sizeof(ff));
        ff.name = fld.name.c_str();
        ff.type = fld.type.c_str();
        ff.is_static = fld.is_static ? 1 : 0;
        field_feats.push_back(ff);
      }

      const size_t method_begin = method_feats.size();
      for (const DexAnalysisMethod& m : c.methods) {
        const size_t param_begin = ptr_pool.size();
        for (const std::string& p : m.params) ptr_pool.push_back(p.c_str());
        const size_t str_begin = ptr_pool.size();
        for (const std::string& s : m.strings) ptr_pool.push_back(s.c_str());

        MethodFeature f;
        memset(&f, 0, sizeof(f));
        f.method_name = m.method_name.c_str();
        f.return_type = m.return_type.c_str();
        f.params = m.params.empty() ? nullptr : &ptr_pool[param_begin];
        f.param_count = m.params.size();
        f.is_direct = m.is_direct ? 1 : 0;
        f.known = m.known ? 1 : 0;
        f.has_opcode_crc = m.has_opcode_crc ? 1 : 0;
        f.opcode_crc = m.opcode_crc;
        f.has_operand_crc = m.has_operand_crc ? 1 : 0;
        f.operand_crc = m.operand_crc;
        f.strings = m.strings.empty() ? nullptr : &ptr_pool[str_begin];
        f.string_count = m.strings.size();
        method_feats.push_back(f);
      }

      ClassFeature cf;
      memset(&cf, 0, sizeof(cf));
      cf.class_path = c.class_path.c_str();
      cf.super_class = c.super_class.c_str();
      cf.source_file = c.source_file.c_str();
      cf.fields = c.fields.empty() ? nullptr : &field_feats[field_begin];
      cf.field_count = c.fields.size();
      cf.methods = c.methods.empty() ? nullptr : &method_feats[method_begin];
      cf.method_count = c.methods.size();
      class_feats.push_back(cf);
    }

    report.classes = class_feats.empty() ? nullptr : class_feats.data();
    report.class_count = class_feats.size();
  }

  cb(&report, user_data);
}

int Engine::ScanFile(IFileID* file_id, IScanner* apk_scanner,
                     IScanner* dex_scanner, const char* path, ScanCallback cb,
                     void* user_data) {
  FileSource source{};
  source.mode = 0;
  source.name = BaseName(path);
  source.path = path;

  ObjPtr<IFileStream> stream = MakeFilestream();
  if (!stream || 0 != stream->Init(&source)) {
    AAV_LOGE("engine: cannot open %s", path);
    return -1;
  }

  FileType type = kFileTypeUnknown;
  if (0 != file_id->GetFileType(stream.get(), &type)) {
    AAV_LOGD("engine: unknown file type %s", path);
    return -1;
  }

  ScanResultPtr result;
  if (kFileTypeZip == type) {
    if (!config_.scan_apk) return 0;
    // The APK scanner locates classes.dex and runs the DEX detection.
    if (0 != apk_scanner->ScanStream(stream.get(), &scan_option_, result)) {
      AAV_LOGE("engine: apk scan failed %s", path);
      return -1;
    }
  } else if (kFileTypeDex == type) {
    if (!config_.scan_dex) return 0;
    ObjPtr<IFileTarget> target = MakeFiletarget();
    if (!target || 0 != target->Init(&source)) return -1;
    if (0 != dex_scanner->ScanTarget(target.get(), &scan_option_, result)) {
      AAV_LOGE("engine: dex scan failed %s", path);
      return -1;
    }
  } else {
    AAV_LOGD("engine: unsupported file type %s", path);
    return 0;
  }

  Emit(path, result.get(), cb, user_data);
  return 0;
}

int Engine::ScanOne(const char* path, ScanCallback cb, void* user_data) {
  return ScanFile(file_id_.get(), apk_scanner_.get(), dex_scanner_.get(), path,
                  cb, user_data);
}

int Engine::ScanBuffer(const void* data, size_t size, const char* name,
                       ScanCallback cb, void* user_data) {
  if (nullptr == data || 0 == size || nullptr == cb || !sig_mgr_) return -1;
  const char* label = (name && name[0]) ? name : "<memory>";

  // Wrap the buffer in a MemStream for identification (and, for an APK, the
  // stream-based scan) -- the in-memory counterpart of the file path.
  MemSource stream_src{};
  stream_src.mode = 0;  // O_RDONLY
  stream_src.name = label;
  stream_src.buf = const_cast<void*>(data);
  stream_src.buf_size = static_cast<int32_t>(size);

  ObjPtr<IMemStream> stream = MakeMemstream();
  if (!stream || 0 != stream->Init(&stream_src)) {
    AAV_LOGE("engine: cannot wrap in-memory image (%s)", label);
    return -1;
  }

  FileType type = kFileTypeUnknown;
  if (0 != file_id_->GetFileType(stream.get(), &type)) {
    AAV_LOGD("engine: unknown in-memory image type (%s)", label);
    return -1;
  }

  ScanResultPtr result;
  if (kFileTypeZip == type) {
    if (!config_.scan_apk) return 0;
    if (0 != apk_scanner_->ScanStream(stream.get(), &scan_option_, result)) {
      AAV_LOGE("engine: apk scan failed (%s)", label);
      return -1;
    }
  } else if (kFileTypeDex == type) {
    if (!config_.scan_dex) return 0;
    MemSource dex_src{};
    dex_src.mode = 0;
    dex_src.name = label;
    dex_src.buf = const_cast<void*>(data);
    dex_src.buf_size = static_cast<int32_t>(size);
    ObjPtr<IMemTarget> target = MakeMemtarget();
    if (!target || 0 != target->Init(&dex_src)) return -1;
    if (0 != dex_scanner_->ScanTarget(target.get(), &scan_option_, result)) {
      AAV_LOGE("engine: dex scan failed (%s)", label);
      return -1;
    }
  } else {
    AAV_LOGD("engine: unsupported in-memory image type (%s)", label);
    return 0;
  }

  Emit(label, result.get(), cb, user_data);
  return 0;
}

}  // namespace

IEngine* MakeEngine() { return new (std::nothrow) Engine; }

}  // namespace aav
