#include <cstdint>

#include <cstring>
#include <vector>

#include "aav/factory.h"
#include "aav/file_id_interface.h"
#include "aav/mem_source.h"
#include "aav/mem_stream_interface.h"
#include "aav/mem_target_interface.h"
#include "doctest.h"

using namespace aav;

static ObjPtr<IMemTarget> MakeTarget(std::vector<uint8_t>& buf) {
  ObjPtr<IMemTarget> t = MakeMemtarget();
  REQUIRE(t);
  MemSource src{};
  src.mode = 0;
  src.name = "t";
  src.buf = buf.data();
  src.buf_size = static_cast<int32_t>(buf.size());
  REQUIRE(t->Init(&src) == 0);
  return t;
}

TEST_CASE("FileID identifies DEX by magic (target and stream)") {
  std::vector<uint8_t> buf(32, 0);
  const uint8_t dex[8] = {0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00};
  memcpy(buf.data(), dex, 8);

  ObjPtr<IFileID> id = MakeFileid();
  REQUIRE(id);

  ObjPtr<IMemTarget> t = MakeTarget(buf);
  FileType ft = kFileTypeUnknown;
  CHECK(id->GetFileType(t.get(), &ft) == 0);
  CHECK(ft == kFileTypeDex);

  ObjPtr<IMemStream> s = MakeMemstream();
  REQUIRE(s);
  MemSource src{};
  src.mode = 0;
  src.name = "t";
  src.buf = buf.data();
  src.buf_size = static_cast<int32_t>(buf.size());
  REQUIRE(s->Init(&src) == 0);
  ft = kFileTypeUnknown;
  CHECK(id->GetFileType(s.get(), &ft) == 0);
  CHECK(ft == kFileTypeDex);
}

TEST_CASE("FileID identifies ZIP/APK by magic") {
  std::vector<uint8_t> buf(32, 0);
  const uint8_t zip[4] = {'P', 'K', 0x03, 0x04};
  memcpy(buf.data(), zip, 4);

  ObjPtr<IFileID> id = MakeFileid();
  REQUIRE(id);
  ObjPtr<IMemTarget> t = MakeTarget(buf);
  FileType ft = kFileTypeUnknown;
  CHECK(id->GetFileType(t.get(), &ft) == 0);
  CHECK(ft == kFileTypeZip);
}

TEST_CASE("FileID reports unknown for unrecognized magic") {
  std::vector<uint8_t> buf(32, 0xAB);
  ObjPtr<IFileID> id = MakeFileid();
  REQUIRE(id);
  ObjPtr<IMemTarget> t = MakeTarget(buf);
  FileType ft = kFileTypeDex;  // seed with a non-unknown value
  int rc = id->GetFileType(t.get(), &ft);
  CHECK((rc != 0 || ft == kFileTypeUnknown));
}
