// End-to-end memory-scan check: drive aav::IEngine::ScanBuffer with a DEX and
// an APK read into RAM (no file path reaches the engine). Exits non-zero unless
// both detect the sample signatures (1001 path + 1002 code). Args:
// <signature-db> <sample.dex> <sample.apk>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

#include "aav/engine_interface.h"

namespace {

struct Check {
  bool malware = false;
  bool has_1001 = false;
  bool has_1002 = false;
};

void OnReport(const aav::ScanReport* report, void* user_data) {
  Check* c = static_cast<Check*>(user_data);
  c->malware = report->is_malware != 0;
  for (size_t i = 0; i < report->sig_count; i++) {
    if (report->sig_ids[i] == 1001) c->has_1001 = true;
    if (report->sig_ids[i] == 1002) c->has_1002 = true;
  }
}

std::string ReadAll(const char* path) {
  std::ifstream f(path, std::ios::binary);
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

int CheckBuffer(aav::IEngine* engine, const std::string& bytes,
                const char* label) {
  Check c;
  if (0 !=
      engine->ScanBuffer(bytes.data(), bytes.size(), label, OnReport, &c)) {
    printf("FAIL: ScanBuffer(%s) returned an error\n", label);
    return 1;
  }
  if (!c.malware || !c.has_1001 || !c.has_1002) {
    printf("FAIL: %s not detected (malware=%d 1001=%d 1002=%d)\n", label,
           c.malware, c.has_1001, c.has_1002);
    return 1;
  }
  printf("OK: %s detected\n", label);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 4) {
    printf("usage: %s <signature-db> <sample.dex> <sample.apk>\n", argv[0]);
    return 2;
  }
  aav::IEngine* engine = aav::MakeEngine();
  aav::EngineConfig config;
  if (!engine || 0 != engine->Init(argv[1], &config)) {
    printf("FAIL: engine init\n");
    if (engine) engine->Destroy();
    return 2;
  }

  std::string dex = ReadAll(argv[2]);
  std::string apk = ReadAll(argv[3]);
  int rc = 0;
  if (dex.empty() || apk.empty()) {
    printf("FAIL: could not read sample.dex / sample.apk\n");
    rc = 2;
  } else {
    rc |= CheckBuffer(engine, dex, "dex-in-memory");
    rc |= CheckBuffer(engine, apk, "apk-in-memory");
  }

  engine->Destroy();
  return rc ? 1 : 0;
}
