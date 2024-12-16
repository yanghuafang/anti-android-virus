#include <cstdint>

#include <cstring>
#include <vector>

#include "aav/factory.h"
#include "aav/file_source.h"
#include "aav/file_stream_interface.h"
#include "aav/file_target_interface.h"
#include "aav/mem_source.h"
#include "aav/mem_stream_interface.h"
#include "aav/mem_target_interface.h"
#include "aav/module_interface.h"
#include "doctest.h"
#include "test_support.h"

using namespace aav;

TEST_CASE("MemStream reads, seeks, tells, and exposes a view") {
  std::vector<uint8_t> data(256);
  for (int i = 0; i < 256; ++i) data[i] = static_cast<uint8_t>(i);

  ObjPtr<IMemStream> s = MakeMemstream();
  REQUIRE(s);
  MemSource src{};
  src.mode = 0;
  src.name = "mem";
  src.buf = data.data();
  src.buf_size = static_cast<int32_t>(data.size());
  REQUIRE(s->Init(&src) == 0);

  int64_t size = 0;
  CHECK(s->GetSize(&size) == 0);
  CHECK(size == 256);

  uint8_t buf[16];
  int got = 0;
  CHECK(s->Read(buf, 16, &got) == 0);
  CHECK(got == 16);
  CHECK(buf[0] == 0);
  CHECK(buf[15] == 15);

  int64_t pos = 0;
  CHECK(s->Tell(&pos) == 0);
  CHECK(pos == 16);
  CHECK(s->Seek(0, 0) == 0);  // SEEK_SET
  CHECK(s->Tell(&pos) == 0);
  CHECK(pos == 0);
  CHECK(s->Seek(0, 2) == 0);  // SEEK_END
  CHECK(s->Tell(&pos) == 0);
  CHECK(pos == 256);

  const void* view = nullptr;
  int64_t view_size = 0;
  CHECK(s->GetView(&view, &view_size) == 0);
  REQUIRE(view != nullptr);
  CHECK(view_size == 256);
  CHECK(memcmp(view, data.data(), 256) == 0);
}

TEST_CASE("MemTarget exposes its whole buffer") {
  std::vector<uint8_t> data(64, 0x5A);
  ObjPtr<IMemTarget> t = MakeMemtarget();
  REQUIRE(t);
  MemSource src{};
  src.mode = 0;
  src.name = "mem";
  src.buf = data.data();
  src.buf_size = static_cast<int32_t>(data.size());
  REQUIRE(t->Init(&src) == 0);

  int64_t size = 0;
  CHECK(t->GetSize(&size) == 0);
  CHECK(size == 64);
  void* buf = nullptr;
  CHECK(t->GetBuf(&buf) == 0);
  CHECK(buf == data.data());
}

TEST_CASE("FileTarget maps a file and exposes its bytes") {
  std::vector<uint8_t> data(200);
  for (size_t i = 0; i < data.size(); ++i)
    data[i] = static_cast<uint8_t>(i * 7 + 1);
  aav_test::TempFile tf =
      aav_test::MakeTempFile(".bin", data.data(), data.size());

  ObjPtr<IFileTarget> t = MakeFiletarget();
  REQUIRE(t);
  const std::string path = tf.str();
  FileSource src{};
  src.mode = 0;
  src.name = "f";
  src.path = path.c_str();
  REQUIRE(t->Init(&src) == 0);

  int64_t size = 0;
  CHECK(t->GetSize(&size) == 0);
  CHECK(size == static_cast<int64_t>(data.size()));
  void* buf = nullptr;
  CHECK(t->GetBuf(&buf) == 0);
  REQUIRE(buf != nullptr);
  CHECK(memcmp(buf, data.data(), data.size()) == 0);
}

TEST_CASE("FileStream reads and memory-maps a file") {
  std::vector<uint8_t> data(300);
  for (size_t i = 0; i < data.size(); ++i)
    data[i] = static_cast<uint8_t>(i & 0xff);
  aav_test::TempFile tf =
      aav_test::MakeTempFile(".bin", data.data(), data.size());

  ObjPtr<IFileStream> s = MakeFilestream();
  REQUIRE(s);
  const std::string path = tf.str();
  FileSource src{};
  src.mode = 0;
  src.name = "f";
  src.path = path.c_str();
  REQUIRE(s->Init(&src) == 0);

  int64_t size = 0;
  CHECK(s->GetSize(&size) == 0);
  CHECK(size == static_cast<int64_t>(data.size()));

  uint8_t buf[50];
  int got = 0;
  CHECK(s->Read(buf, 50, &got) == 0);
  CHECK(got == 50);
  CHECK(buf[0] == 0);
  CHECK(buf[49] == 49);

  const void* view = nullptr;
  int64_t view_size = 0;
  CHECK(s->GetView(&view, &view_size) == 0);
  REQUIRE(view != nullptr);
  CHECK(view_size == static_cast<int64_t>(data.size()));
  CHECK(memcmp(view, data.data(), data.size()) == 0);
}

TEST_CASE("Module reports failure for a missing library") {
  ObjPtr<IModule> m = MakeModule();
  REQUIRE(m);
  CHECK(m->Load("/no/such/aav-library.so.does-not-exist") != 0);
  void* addr = nullptr;
  CHECK(m->GetFuncAddress("nonexistent_symbol", &addr) != 0);
}
