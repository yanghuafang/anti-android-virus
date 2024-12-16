#ifndef AAV_ENGINE_INTERFACE_H_
#define AAV_ENGINE_INTERFACE_H_

#include <stddef.h>
#include <stdint.h>

#include "aav/object_interface.h"

namespace aav {

// Configuration for IEngine::Init. Plain data (no std:: types) so the SDK ABI
// is stable across compilers and stdlib versions.
struct EngineConfig {
  int scan_apk = 1;      // scan APK (zip) containers
  int scan_dex = 1;      // scan DEX files
  int recurse_dirs = 1;  // when a directory is scanned, descend into it
  int verbose = 0;       // emit engine diagnostics (stderr / logcat)
  int analysis = 0;      // record per-method features (slower)
  int scan_threads = 1;  // worker threads for directory scans (1 = sequential;
                         // only directory scans are parallelized)
};

// A declared field of a class (analysis only). `type` is a DEX type descriptor
// (e.g. "Landroid/os/Bundle;"). Engine-owned; valid only for the callback.
struct FieldFeature {
  const char* name;
  const char* type;
  int is_static;
};

// Per-method feature record, present only when EngineConfig::analysis is set.
// `return_type`/`params` are DEX type descriptors and disambiguate overloads.
// All pointers are engine-owned and valid only for the duration of the
// ScanCallback that delivers the enclosing ScanReport.
struct MethodFeature {
  const char* method_name;
  const char* return_type;    // DEX type descriptor (may be empty)
  const char* const* params;  // params[0 .. param_count) (DEX descriptors)
  size_t param_count;
  int is_direct;  // direct (static/private/ctor) vs virtual
  int known;      // matched an existing signature
  int has_opcode_crc;
  uint32_t opcode_crc;
  int has_operand_crc;
  uint32_t operand_crc;
  const char* const* strings;  // strings[0 .. string_count)
  size_t string_count;
};

// Per-class record (analysis only): the class plus its fields and methods.
// `class_path` is the regularized dotted/lower-case path; `super_class` is a
// DEX type descriptor (may be empty). Engine-owned; valid only for the
// callback.
struct ClassFeature {
  const char* class_path;
  const char* super_class;
  const char* source_file;
  const FieldFeature* fields;  // fields[0 .. field_count)
  size_t field_count;
  const MethodFeature* methods;  // methods[0 .. method_count)
  size_t method_count;
};

// One scanned file's result. All pointers are engine-owned and valid only for
// the duration of the ScanCallback; copy anything you need to outlive the call.
struct ScanReport {
  const char* path;
  int is_malware;
  int is_white;
  const uint32_t* sig_ids;   // sig_ids[0 .. sig_count)
  const char* const* names;  // names[i] names sig_ids[i], e.g.
                             // "Trojan!SampleFam.a@Android.Dex"
  size_t sig_count;
  const ClassFeature* classes;  // classes[0 .. class_count) (analysis only)
  size_t class_count;
};

// Result callback, invoked once per scanned file. `report` (and everything it
// points to) is engine-owned and valid only for the duration of this call --
// copy anything you need to outlive it. `user_data` is the opaque pointer you
// handed to Scan / ScanBuffer; the engine passes it straight back (never
// dereferencing it), so you can thread your own context -- a results container,
// counters, a `this` pointer, etc. -- into the callback instead of using
// globals. Pass nullptr if you don't need it.
//
// Threading: with EngineConfig::scan_threads > 1 a directory scan runs on
// internal worker threads, so `cb` may be invoked from a thread other than the
// one that called Scan(). The engine serializes the invocations, so `cb` is
// never called concurrently and needs no locking of its own.
typedef void (*ScanCallback)(const ScanReport* report, void* user_data);

// High-level scanning facade. It hides file identification, signature-database
// loading, scanner selection, APK unpacking and directory traversal. Only PODs,
// C strings and a function pointer cross this boundary, so it is ABI-stable.
class IEngine : public IObject {
 public:
  // Load the signature database and prepare the scanners. Returns 0 on success.
  virtual int Init(const char* sig_db_path, const EngineConfig* config) = 0;

  // Scan a single file or a directory (walked recursively when recurse_dirs is
  // set), invoking `cb` once per scanned *.apk / *.dex (APKs are unpacked and
  // their classes.dex scanned). `user_data` is forwarded unchanged to every
  // `cb` call (see ScanCallback). Returns 0 on success.
  virtual int Scan(const char* path, ScanCallback cb, void* user_data) = 0;

  // Scan an in-memory image (APK/zip or DEX, auto-detected) with no file on
  // disk -- useful for gateway scanning. `name` only labels the report (may be
  // null). `cb` is invoked once with `user_data` forwarded through (see
  // ScanCallback). Returns 0 on success.
  virtual int ScanBuffer(const void* data, size_t size, const char* name,
                         ScanCallback cb, void* user_data) = 0;
};

// Construct the engine (returns nullptr on failure). Release it with
// engine->Destroy() when done.
IEngine* MakeEngine();

}  // namespace aav

#endif
