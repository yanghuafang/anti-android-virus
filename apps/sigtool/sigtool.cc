// sigtool - developer tooling for the aav engine.
//
//   sigtool gen-sample <out_dir> [--dex-version NNN]   (NNN in 035..040)
//
// writes two mutually-consistent files the engine can load and detect:
//
//   <out_dir>/sample.dex  - a tiny, well-formed DEX (Evil: path-sig match,
//                           Worker.work(): code-sig + AND-logic match)
//   <out_dir>/sample.sig  - the matching encrypted + gzipped signature DB
//
// The fixtures are produced by the shared generator in sample_data.{h,cc},
// which the unit tests reuse so the tool and the tests never drift apart.

#include <cstdio>
#include <filesystem>
#include <string>

#include "sample_data.h"

namespace fs = std::filesystem;
using aav::sample::Bytes;

static bool WriteFile(const fs::path& p, const Bytes& data) {
  FILE* f = fopen(p.string().c_str(), "wb");
  if (!f) return false;
  bool ok = fwrite(data.data(), 1, data.size(), f) == data.size();
  return fclose(f) == 0 && ok;
}

static int GenSample(const std::string& out_dir, const std::string& version) {
  std::error_code ec;
  fs::create_directories(out_dir, ec);

  Bytes dex = aav::sample::BuildSampleDex(version);
  Bytes sig = aav::sample::BuildSampleSig();

  fs::path dex_path = fs::path(out_dir) / "sample.dex";
  fs::path sig_path = fs::path(out_dir) / "sample.sig";
  if (!WriteFile(dex_path, dex)) {
    fprintf(stderr, "sigtool: failed to write %s\n", dex_path.string().c_str());
    return 1;
  }
  if (!WriteFile(sig_path, sig)) {
    fprintf(stderr, "sigtool: failed to write %s\n", sig_path.string().c_str());
    return 1;
  }
  fprintf(stdout, "wrote %s (%zu bytes)\n", dex_path.string().c_str(),
          dex.size());
  fprintf(stdout, "wrote %s (%zu bytes)\n", sig_path.string().c_str(),
          sig.size());
  fprintf(stdout, "try: aavscan %s %s\n", sig_path.string().c_str(),
          dex_path.string().c_str());
  return 0;
}

int main(int argc, char** argv) {
  if (argc >= 2 && std::string(argv[1]) == "gen-sample") {
    std::string out_dir = ".";
    std::string version = "035";
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--dex-version" && i + 1 < argc)
        version = argv[++i];
      else if (!a.empty() && a[0] != '-')
        out_dir = a;
    }
    if (version.size() != 3) {
      fprintf(stderr, "sigtool: --dex-version must be 3 digits, e.g. 039\n");
      return 2;
    }
    return GenSample(out_dir, version);
  }
  fprintf(stderr, "usage: %s gen-sample <out_dir> [--dex-version NNN]\n",
          argv[0]);
  return 2;
}
