// aavscan: a thin command-line front-end for the aav engine. It is a pure
// consumer of the public facade (aav/engine_interface.h) -- init, scan (results
// arrive through a callback), print.

#include <string.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>

#include "aav/engine_interface.h"

namespace {

// Per-scan state, threaded through Scan()'s opaque `user` pointer and updated
// in the callback -- the plain function-pointer callback carries no state
// itself.
struct ScanStats {
  int file_count = 0;
  int flagged = 0;
};

void PrintMethod(const aav::MethodFeature& m) {
  printf("      %smethod %s(", m.is_direct ? "" : "virtual ",
         m.method_name ? m.method_name : "");
  for (size_t p = 0; p < m.param_count; p++)
    printf("%s%s", p ? ", " : "", m.params[p]);
  printf(")%s%s\n", m.return_type ? m.return_type : "",
         m.known ? "  [known]" : "");
  if (m.has_opcode_crc) printf("        opcodeCRC32:  0x%08x\n", m.opcode_crc);
  if (m.has_operand_crc)
    printf("        operandCRC32: 0x%08x\n", m.operand_crc);
  for (size_t j = 0; j < m.string_count; j++)
    printf("          \"%s\"\n", m.strings[j]);
}

void PrintAnalysis(const aav::ScanReport& report) {
  if (0 == report.class_count) return;
  printf("  analysis: %zu class(es)\n", report.class_count);
  for (size_t i = 0; i < report.class_count; i++) {
    const aav::ClassFeature& c = report.classes[i];
    printf("    class %s", c.class_path ? c.class_path : "");
    if (c.super_class && c.super_class[0]) printf(" : %s", c.super_class);
    if (c.source_file && c.source_file[0]) printf("  (%s)", c.source_file);
    printf("\n");
    for (size_t f = 0; f < c.field_count; f++)
      printf("      %sfield %s : %s\n", c.fields[f].is_static ? "static " : "",
             c.fields[f].name ? c.fields[f].name : "",
             c.fields[f].type ? c.fields[f].type : "");
    for (size_t m = 0; m < c.method_count; m++) PrintMethod(c.methods[m]);
  }
}

// aav::ScanCallback: invoked once per scanned file; `user_data` is the
// ScanStats we passed to Scan().
void OnReport(const aav::ScanReport* report, void* user_data) {
  ScanStats* stats = static_cast<ScanStats*>(user_data);
  stats->file_count++;
  if (report->is_malware) stats->flagged++;
  printf("file: %s\n", report->path);
  printf("  isMalware: %d  isWhite: %d\n", report->is_malware,
         report->is_white);
  for (size_t i = 0; i < report->sig_count; i++) {
    printf("  sigID: %u", report->sig_ids[i]);
    if (report->names && report->names[i]) printf("  %s", report->names[i]);
    printf("\n");
  }
  PrintAnalysis(*report);
}

}  // namespace

int main(int argc, char** argv) {
  const char* sig_path = nullptr;
  const char* target_path = nullptr;
  aav::EngineConfig config;
  for (int i = 1; i < argc; i++) {
    if (0 == strcmp(argv[i], "--debug")) {
      config.verbose = 1;
    } else if (0 == strcmp(argv[i], "--analysis")) {
      config.analysis = 1;
    } else if (0 == strcmp(argv[i], "--mt")) {
      if (i + 1 >= argc) {
        fprintf(stderr, "aavscan: --mt requires a thread count\n");
        return 2;
      }
      const int t = atoi(argv[++i]);
      config.scan_threads = (t > 0) ? t : 1;
    } else if (nullptr == sig_path) {
      sig_path = argv[i];
    } else if (nullptr == target_path) {
      target_path = argv[i];
    }
  }
  if (nullptr == sig_path || nullptr == target_path) {
    fprintf(stderr,
            "usage: aavscan [--debug] [--analysis] [--mt <threads>] "
            "<signature-db> <apk|dex file or dir>\n");
    return 2;
  }

  aav::IEngine* engine = aav::MakeEngine();
  if (nullptr == engine || 0 != engine->Init(sig_path, &config)) {
    fprintf(stderr, "aavscan: failed to initialize engine (signature db: %s)\n",
            sig_path);
    if (engine) engine->Destroy();
    return 1;
  }

  ScanStats stats;
  const auto start = std::chrono::steady_clock::now();
  int rc = engine->Scan(target_path, OnReport, &stats);
  const std::chrono::duration<double> elapsed =
      std::chrono::steady_clock::now() - start;
  engine->Destroy();

  if (0 != rc) {
    fprintf(stderr, "aavscan: scan failed: %s\n", target_path);
    return 1;
  }
  printf("scanned %d file(s), %d flagged, %.3fs\n", stats.file_count,
         stats.flagged, elapsed.count());
  return 0;
}
