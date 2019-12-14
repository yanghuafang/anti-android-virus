#ifndef AAV_ENGINE_INTERFACE_H_
#define AAV_ENGINE_INTERFACE_H_

#include <cstddef>
#include <cstdint>

#include "aav/object_interface.h"

namespace aav {

/// Configuration for IEngine::Init. Plain data (no std:: types) so the SDK ABI
/// is stable across compilers and stdlib versions.
struct EngineConfig {
  int scan_apk = 1;      ///< scan APK (zip) containers
  int scan_dex = 1;      ///< scan DEX files
  int recurse_dirs = 1;  ///< when a directory is scanned, descend into it
  int verbose = 0;       ///< emit engine diagnostics (stderr / logcat)
  int scan_threads = 1;  ///< worker threads for directory scans (1 =
                         ///< sequential; only directory scans are parallelized)
};

/// One scanned file's result. All pointers are engine-owned and valid only for
/// the duration of the ScanCallback; copy anything you need to outlive the
/// call.
struct ScanReport {
  const char* path;
  int is_malware;
  int is_white;
  const uint32_t* sig_ids;   ///< sig_ids[0 .. sig_count)
  const char* const* names;  ///< names[i] names sig_ids[i], e.g.
                             ///< "Trojan!SampleFam.a@Android.Dex"
  size_t sig_count;
};

/// Result callback, invoked once per scanned file. `report` (and everything it
/// points to) is engine-owned and valid only for the duration of this call --
/// copy anything you need to outlive it. `user_data` is the opaque pointer you
/// handed to Scan / ScanBuffer; the engine passes it straight back (never dereferencing it),
/// so you can thread your own context -- a results container, counters, a
/// `this` pointer, etc. -- into the callback instead of using globals. Pass
/// nullptr if you don't need it.
using ScanCallback = void (*)(const ScanReport* report, void* user_data);

/// High-level scanning facade. It hides file identification, signature-database
/// loading, scanner selection, APK unpacking and directory traversal. Only
/// PODs, C strings and
/// a function pointer cross this boundary, so it is ABI-stable.
class IEngine : public IObject {
 public:
  /// Load the signature database and prepare the scanners. Returns 0 on
  /// success.
  virtual int Init(const char* sig_db_path, const EngineConfig* config) = 0;

  /// Scan a single file or a directory (walked recursively when recurse_dirs is
  /// set), invoking `cb` once per scanned *.apk / *.dex (APKs are unpacked and
  /// their classes.dex scanned). `user_data` is forwarded unchanged to every
  /// `cb` call (see ScanCallback). Returns 0 on success.
  virtual int Scan(const char* path, ScanCallback cb, void* user_data) = 0;

  /// Scan an in-memory image (APK/zip or DEX, auto-detected) with no file on
  /// disk -- useful for gateway scanning. `name` only labels the report (may be null). `cb` is invoked
  /// once with `user_data` forwarded through (see ScanCallback). Returns 0 on
  /// success.
  virtual int ScanBuffer(const void* data, size_t size, const char* name,
                         ScanCallback cb, void* user_data) = 0;
};

/// Construct the engine (returns nullptr on failure). Release it with
/// engine->Destroy() when done.
IEngine* MakeEngine();

}  // namespace aav

#endif
