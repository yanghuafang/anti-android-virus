#ifndef AAV_TEST_SUPPORT_H_
#define AAV_TEST_SUPPORT_H_

#include <cstdio>
#include <filesystem>
#include <string>
#include <utility>

// Small helpers shared by the unit tests that need a real file on disk.
namespace aav_test {

// Writes `size` bytes to a uniquely-named file in the temp dir; returns the
// path. Prefer TempFile below for automatic cleanup.
inline std::filesystem::path WriteTempFile(const std::string& suffix,
                                           const void* data, size_t size) {
  static int counter = 0;
  std::filesystem::path p =
      std::filesystem::temp_directory_path() /
      ("aav_ut_" + std::to_string(counter++) + suffix);
  FILE* f = fopen(p.string().c_str(), "wb");
  if (f) {
    if (size) fwrite(data, 1, size, f);
    fclose(f);
  }
  return p;
}

// RAII temp file: removes itself on destruction.
struct TempFile {
  std::filesystem::path path;
  explicit TempFile(std::filesystem::path p) : path(std::move(p)) {}
  ~TempFile() {
    std::error_code ec;
    std::filesystem::remove(path, ec);
  }
  std::string str() const { return path.string(); }
};

inline TempFile MakeTempFile(const std::string& suffix, const void* data,
                             size_t size) {
  return TempFile(WriteTempFile(suffix, data, size));
}

}  // namespace aav_test

#endif
