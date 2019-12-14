// aavscan: a thin command-line front-end for the aav engine. It is a pure
// consumer of the public facade (aav/engine_interface.h) -- init, scan (results
// arrive through a callback), print.

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "aav/engine_interface.h"

namespace {

constexpr int kMaxScanThreads = 1024;

// Per-scan state, threaded through Scan()'s opaque `user` pointer and updated
// in the callback -- the plain function-pointer callback carries no state
// itself.
struct ScanStats {
  int file_count = 0;
  int flagged = 0;
};

// aav::ScanCallback: invoked once per scanned file; `user_data` is the
// ScanStats we passed to Scan().
void OnReport(const aav::ScanReport* report, void* user_data) {
  ScanStats* stats = static_cast<ScanStats*>(user_data);
  stats->file_count++;
  if (report->is_malware) {
    stats->flagged++;
  }
  std::printf("file: %s\n", report->path);
  std::printf("  isMalware: %d  isWhite: %d\n", report->is_malware,
              report->is_white);
  for (size_t i = 0; i < report->sig_count; i++) {
    std::printf("  sigID: %u", report->sig_ids[i]);
    if (report->names && report->names[i]) {
      std::printf("  %s", report->names[i]);
    }
    std::printf("\n");
  }
}

}  // namespace

int main(int argc, char** argv) {
  const char* sig_path = nullptr;
  const char* target_path = nullptr;
  aav::EngineConfig config;
  for (int i = 1; i < argc; i++) {
    if (0 == std::strcmp(argv[i], "--debug")) {
      config.verbose = 1;
    } else if (0 == std::strcmp(argv[i], "--mt")) {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "aavscan: --mt requires a thread count\n");
        return 2;
      }
      // strtol, not atoi: atoi cannot distinguish "0" from unparseable
      // input, so `--mt abc` silently became 1 thread.
      char* end = nullptr;
      errno = 0;
      const int64_t t = std::strtol(argv[++i], &end, 10);
      if (errno != 0 || end == argv[i] || *end != '\0' || t < 1 ||
          t > kMaxScanThreads) {
        std::fprintf(stderr, "aavscan: --mt wants 1..%d, got '%s'\n",
                     kMaxScanThreads, argv[i]);
        return 2;
      }
      config.scan_threads = static_cast<int>(t);
    } else if (nullptr == sig_path) {
      sig_path = argv[i];
    } else if (nullptr == target_path) {
      target_path = argv[i];
    }
  }
  if (nullptr == sig_path || nullptr == target_path) {
    std::fprintf(stderr,
                 "usage: aavscan [--debug] [--mt <threads>] "
                 "<signature-db> <apk|dex file or dir>\n");
    return 2;
  }

  aav::IEngine* engine = aav::MakeEngine();
  if (nullptr == engine || 0 != engine->Init(sig_path, &config)) {
    std::fprintf(stderr,
                 "aavscan: failed to initialize engine (signature db: %s)\n",
                 sig_path);
    if (engine) {
      engine->Destroy();
    }
    return 1;
  }

  ScanStats stats;
  const auto start = std::chrono::steady_clock::now();
  int rc = engine->Scan(target_path, OnReport, &stats);
  const std::chrono::duration<double> elapsed =
      std::chrono::steady_clock::now() - start;
  engine->Destroy();

  if (0 != rc) {
    std::fprintf(stderr, "aavscan: scan failed: %s\n", target_path);
    return 1;
  }
  std::printf("scanned %d file(s), %d flagged, %.3fs\n", stats.file_count,
              stats.flagged, elapsed.count());
  return 0;
}
