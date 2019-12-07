#include <cstring>
#include <filesystem>
#include <new>
#include <string>
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
#include "utils/log.h"  // internal: runtime log level

namespace aav {
namespace {

const char* BaseName(const char* path) {
  const char* slash = std::strrchr(path, '/');
  return slash ? slash + 1 : path;
}

bool EndsWith(const std::string& s, const char* suffix) {
  size_t n = std::strlen(suffix);
  return s.size() >= n && 0 == s.compare(s.size() - n, n, suffix);
}

class Engine : public IEngine {
 public:
  int Init(const char* sig_db_path, const EngineConfig* config) override;
  int Scan(const char* path, ScanCallback cb, void* user_data) override;
  int ScanBuffer(const void* data, size_t size, const char* name,
                 ScanCallback cb, void* user_data) override;

 private:
  int ScanOne(const char* path, ScanCallback cb, void* user_data);
  void ScanDir(const char* dir, ScanCallback cb, void* user_data);
  // Build a POD ScanReport (backed by engine-owned storage valid only for the
  // duration of the call) and hand it to the callback.
  void Emit(const char* path, const ScanResult* result, ScanCallback cb,
            void* user_data);

  ObjPtr<IFileId> file_id_;
  ObjPtr<ISigMgr> sig_mgr_;
  ObjPtr<IScanner> apk_scanner_;
  ObjPtr<IScanner> dex_scanner_;
  ScanOption scan_option_{};
  EngineConfig config_{};
};

int Engine::Init(const char* sig_db_path, const EngineConfig* config) {
  if (nullptr == sig_db_path) {
    return -1;
  }
  if (config) {
    config_ = *config;  // otherwise keep the defaults
  }
  SetLogLevel(config_.verbose ? kLogDebug : kLogError);

  file_id_ = MakeFileId();
  if (!file_id_) {
    return -1;
  }

  sig_mgr_ = MakeSigMgr();
  if (!sig_mgr_ || 0 != sig_mgr_->Init(nullptr)) {
    return -1;
  }
  LoadFormatConfig lfc{};
  lfc.ad = 1;
  lfc.apk = config_.scan_apk ? 1 : 0;
  lfc.dex = config_.scan_dex ? 1 : 0;
  lfc.elf = 0;
  lfc.oat = 0;
  lfc.white = 1;
  lfc.heur = 0;
  lfc.analyzer = 0;
  if (0 != sig_mgr_->LoadSigs(sig_db_path, &lfc)) {
    return -1;
  }

  apk_scanner_ = MakeApkScanner();
  if (!apk_scanner_ || 0 != apk_scanner_->Init(sig_mgr_.get())) {
    return -1;
  }
  dex_scanner_ = MakeDexScanner();
  if (!dex_scanner_ || 0 != dex_scanner_->Init(sig_mgr_.get())) {
    return -1;
  }

  scan_option_.config.unarch = 1;
  scan_option_.config.unpack = 0;
  scan_option_.config.apk = config_.scan_apk ? 1 : 0;
  scan_option_.config.dex = config_.scan_dex ? 1 : 0;
  scan_option_.config.elf = 0;
  scan_option_.config.oat = 0;
  return 0;
}

int Engine::Scan(const char* path, ScanCallback cb, void* user_data) {
  if (nullptr == path || nullptr == cb || !sig_mgr_) {
    return -1;
  }
  std::error_code ec;
  if (std::filesystem::is_directory(path, ec)) {
    ScanDir(path, cb, user_data);
    return 0;
  }
  return ScanOne(path, cb, user_data);
}

void Engine::ScanDir(const char* dir, ScanCallback cb, void* user_data) {
  std::error_code ec;
  std::filesystem::directory_iterator it(dir, ec);
  const std::filesystem::directory_iterator end;
  if (ec) {
    return;
  }
  for (; it != end; it.increment(ec)) {
    if (ec) {
      break;
    }
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

void Engine::Emit(const char* path, const ScanResult* result, ScanCallback cb,
                  void* user_data) {
  // Storage that backs the POD ScanReport; alive until cb returns.
  std::vector<uint32_t> ids;
  std::vector<std::string> name_storage;
  std::vector<const char*> name_ptrs;

  ScanReport report;
  std::memset(&report, 0, sizeof(report));
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
                                        buf, sizeof(buf))) {
        name_storage.emplace_back(buf);
      } else {
        name_storage.emplace_back();
      }
    }
    name_ptrs.reserve(name_storage.size());
    for (const std::string& s : name_storage) {
      name_ptrs.push_back(s.c_str());
    }
    report.sig_ids = ids.empty() ? nullptr : ids.data();
    report.names = name_ptrs.empty() ? nullptr : name_ptrs.data();
    report.sig_count = ids.size();
  }

  cb(&report, user_data);
}

int Engine::ScanOne(const char* path, ScanCallback cb, void* user_data) {
  FileSource source{};
  source.mode = 0;
  source.name = BaseName(path);
  source.path = path;

  ObjPtr<IFileStream> stream = MakeFileStream();
  if (!stream || 0 != stream->Init(&source)) {
    AAV_LOGE("engine: cannot open %s", path);
    return -1;
  }

  FileType type = kFileTypeUnknown;
  if (0 != file_id_->GetFileType(stream.get(), &type)) {
    AAV_LOGD("engine: unknown file type %s", path);
    return -1;
  }

  ScanResultPtr result;
  if (kFileTypeZip == type) {
    if (!config_.scan_apk) {
      return 0;
    }
    // The APK scanner locates classes.dex and runs the DEX detection.
    if (0 != apk_scanner_->ScanStream(stream.get(), &scan_option_, result)) {
      AAV_LOGE("engine: apk scan failed %s", path);
      return -1;
    }
  } else if (kFileTypeDex == type) {
    if (!config_.scan_dex) {
      return 0;
    }
    ObjPtr<IFileTarget> target = MakeFileTarget();
    if (!target || 0 != target->Init(&source)) {
      return -1;
    }
    if (0 != dex_scanner_->ScanTarget(target.get(), &scan_option_, result)) {
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

int Engine::ScanBuffer(const void* data, size_t size, const char* name,
                       ScanCallback cb, void* user_data) {
  if (nullptr == data || 0 == size || nullptr == cb || !sig_mgr_) {
    return -1;
  }
  const char* label = (name && name[0]) ? name : "<memory>";

  // Wrap the buffer in a MemStream for identification -- the in-memory
  // counterpart of the file path.
  MemSource stream_src{};
  stream_src.mode = 0;  // O_RDONLY
  stream_src.name = label;
  stream_src.buf = const_cast<void*>(data);
  stream_src.buf_size = static_cast<int32_t>(size);

  ObjPtr<IMemStream> stream = MakeMemStream();
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
    if (!config_.scan_apk) {
      return 0;
    }
    if (0 != apk_scanner_->ScanStream(stream.get(), &scan_option_, result)) {
      AAV_LOGE("engine: apk scan failed (%s)", label);
      return -1;
    }
  } else if (kFileTypeDex == type) {
    if (!config_.scan_dex) {
      return 0;
    }
    MemSource dex_src{};
    dex_src.mode = 0;
    dex_src.name = label;
    dex_src.buf = const_cast<void*>(data);
    dex_src.buf_size = static_cast<int32_t>(size);
    ObjPtr<IMemTarget> target = MakeMemTarget();
    if (!target || 0 != target->Init(&dex_src)) {
      return -1;
    }
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
