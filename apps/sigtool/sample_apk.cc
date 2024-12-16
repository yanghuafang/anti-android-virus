#include "sample_data.h"

// Kept in its own translation unit: miniz.h defines zlib-compatible names that
// collide with the real <zlib.h> used by sample_data.cc, so the two headers
// must never share a TU.
#ifdef AAV_HAVE_MINIZ

#include <cstring>

#include "miniz.h"

namespace aav {
namespace sample {

Bytes BuildSampleApk(const Bytes& classes_dex, const Bytes& classes2_dex) {
  mz_zip_archive zip;
  memset(&zip, 0, sizeof(zip));
  if (!mz_zip_writer_init_heap(&zip, 0, 0)) return {};
  mz_zip_writer_add_mem(&zip, "classes.dex", classes_dex.data(),
                        classes_dex.size(), MZ_BEST_COMPRESSION);
  if (!classes2_dex.empty()) {
    mz_zip_writer_add_mem(&zip, "classes2.dex", classes2_dex.data(),
                          classes2_dex.size(), MZ_BEST_COMPRESSION);
  }
  void* buf = nullptr;
  size_t size = 0;
  Bytes out;
  if (mz_zip_writer_finalize_heap_archive(&zip, &buf, &size)) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    out.assign(p, p + size);
    mz_free(buf);
  }
  mz_zip_writer_end(&zip);
  return out;
}

}  // namespace sample
}  // namespace aav

#endif  // AAV_HAVE_MINIZ
