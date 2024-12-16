#include "dex_file.h"

#include <assert.h>
#include <string.h>

#include <memory>
#include <new>

#include "aav/target_interface.h"
#include "dex_analysis.h"
#include "dex_code.h"
#include "leb128.h"
#include "log.h"

namespace aav {

uint8_t DEX_FILE_MAGIC[8] = {0x64, 0x65, 0x78, 0x0a,
                             0x30, 0x33, 0x35, 0x00};  //"dex\n035\0"
uint32_t ENDIAN_CONSTANT = 0x12345678;
uint32_t REVERSE_ENDIAN_CONSTANT = 0x78563412;

namespace {
// Accept the DEX magic "dex\n0XY\0" for versions 035..040. Only the "dex\n"
// prefix and the version range are validated; the header and id/class tables
// are identical across these versions, so the structural parser handles them
// uniformly (tail-bytecode differences are handled by DexCode).
bool IsSupportedDexMagic(const uint8_t* magic) {
  if (0 != memcmp(magic, DEX_FILE_MAGIC, 4)) return false;  // "dex\n"
  if (0x00 != magic[7]) return false;
  if ('0' != magic[4]) return false;
  if ('3' == magic[5] && magic[6] >= '5' && magic[6] <= '9') return true;
  if ('4' == magic[5] && '0' == magic[6]) return true;
  return false;
}
}  // namespace

DexFile::DexFile() {
  max_string_id_ = 0;
  max_type_id_ = 0;
  max_proto_id_ = 0;
  max_field_id_ = 0;
  max_method_id_ = 0;
  max_class_def_id_ = 0;
  current_class_idx_ = -1;

  dex_file_buf_ = nullptr;
  target_size_ = 0;
  little_endian_tag_ = true;
}

DexFile::~DexFile() { Uninit(); }

int DexFile::Init(ITarget* target) {
  if (nullptr == target) return -1;

  int64_t target_size = 0;
  if (0 != target->GetSize(&target_size)) return -1;
  target_size_ = static_cast<uint32_t>(target_size);
  if (0 != target->GetBuf(&dex_file_buf_)) return -1;

  dex_format_.reset(new (std::nothrow) DexFormat);
  if (nullptr == dex_format_) return -1;

  if (0 != ParseHeader()) return -1;
  if (0 != ParseStringIDs()) return -1;
  if (0 != ParseTypeIDs()) return -1;
  if (0 != ParseProtoIDs()) return -1;
  if (0 != ParseFieldIDs()) return -1;
  if (0 != ParseMethodIDs()) return -1;
  if (0 != ParseClassDefs()) return -1;

  return 0;
}

int DexFile::Uninit() {
  dex_format_.reset();
  class_data_item_.reset();

  max_string_id_ = 0;
  max_type_id_ = 0;
  max_proto_id_ = 0;
  max_field_id_ = 0;
  max_method_id_ = 0;
  max_class_def_id_ = 0;
  current_class_idx_ = -1;

  dex_file_buf_ = nullptr;
  target_size_ = 0;
  little_endian_tag_ = true;
  return 0;
}

const uint8_t* DexFile::BufEnd() const {
  return static_cast<const uint8_t*>(dex_file_buf_) + target_size_;
}

// Validate that a table of `count` items of `itemSize` bytes starting at file
// offset `off` lies entirely past the header and within the mapped buffer.
bool DexFile::RegionOk(uint32_t off, uint32_t count, uint32_t item_size) const {
  if (0 == count) return true;
  if (off < sizeof(DexHeader)) return false;
  uint64_t end =
      static_cast<uint64_t>(off) + static_cast<uint64_t>(count) * item_size;
  return end <= static_cast<uint64_t>(target_size_);
}

// Advance to the next class. Reads the current class_def's class_data (its
// static/instance fields and direct/virtual methods) and positions the per-list
// iterators that GetDirectMethod/GetVirtualMethod consume. Returns 0 on success
// (class_name set), -2 to skip a malformed or data-less class (the caller
// advances and continues), or -1 to stop iterating (end of the class list, or a
// fatal allocation error). Fields are decoded only in --analysis mode; methods
// are always decoded.
int DexFile::GetClass(std::string& class_name) {
  class_data_item_.reset();

  int ret = -1;
  do {
    if (dex_format_->class_defs.end() == class_defs_itor_) break;

    if (class_defs_itor_->class_idx >= dex_format_->type_ids.size()) {
      ret = -2;
      break;
    }
    int result = GetTypeString(class_defs_itor_->class_idx, class_name);
    if (0 != result) {
      ret = result;
      break;
    }

    if (class_defs_itor_->class_data_off <= 0x70 ||
        class_defs_itor_->class_data_off >= target_size_) {
      ret = -2;
      break;
    }
    assert(class_defs_itor_->class_data_off > 0x70 &&
           class_defs_itor_->class_data_off < target_size_);

    uint8_t* cur = reinterpret_cast<uint8_t*>(
        static_cast<char*>(dex_file_buf_) + class_defs_itor_->class_data_off);
    uint32_t static_fields_size = 0;
    uint32_t instance_fields_size = 0;
    uint32_t direct_methods_size = 0;
    uint32_t virtual_methods_size = 0;
    int bytes_read = 0;

    if (0 != ReadUleb128Safe(cur, BufEnd(), &static_fields_size, &bytes_read))
      break;
    cur += bytes_read;
    if (0 != ReadUleb128Safe(cur, BufEnd(), &instance_fields_size, &bytes_read))
      break;
    cur += bytes_read;
    if (0 != ReadUleb128Safe(cur, BufEnd(), &direct_methods_size, &bytes_read))
      break;
    cur += bytes_read;
    if (0 != ReadUleb128Safe(cur, BufEnd(), &virtual_methods_size, &bytes_read))
      break;
    cur += bytes_read;

    class_data_item_.reset(new (std::nothrow) DexClassData);
    if (nullptr == class_data_item_) break;
    const bool analysis = IsDexAnalysisEnabled();

    bool success = true;
    try {
      // static_fields then instance_fields: each entry is a (field_idx_diff,
      // access_flags) uleb pair. Stored only for --analysis; skipped otherwise.
      for (uint32_t i = 0; i < static_fields_size; i++) {
        DexEncodedField f;
        if (0 !=
            ReadUleb128Safe(cur, BufEnd(), &f.field_idx_diff, &bytes_read)) {
          success = false;
          break;
        }
        cur += bytes_read;
        if (0 != ReadUleb128Safe(cur, BufEnd(), &f.access_flags, &bytes_read)) {
          success = false;
          break;
        }
        cur += bytes_read;
        if (analysis) class_data_item_->static_fields.push_back(f);
      }
      if (!success) break;

      for (uint32_t i = 0; i < instance_fields_size; i++) {
        DexEncodedField f;
        if (0 !=
            ReadUleb128Safe(cur, BufEnd(), &f.field_idx_diff, &bytes_read)) {
          success = false;
          break;
        }
        cur += bytes_read;
        if (0 != ReadUleb128Safe(cur, BufEnd(), &f.access_flags, &bytes_read)) {
          success = false;
          break;
        }
        cur += bytes_read;
        if (analysis) class_data_item_->instance_fields.push_back(f);
      }
      if (!success) break;

      class_data_item_->direct_methods.reserve(direct_methods_size);
      for (uint32_t i = 0; i < direct_methods_size; i++) {
        DexEncodedMethod encoded_method;
        if (0 != ReadUleb128Safe(cur, BufEnd(), &encoded_method.method_idx_diff,
                                 &bytes_read)) {
          success = false;
          break;
        }
        cur += bytes_read;
        if (0 != ReadUleb128Safe(cur, BufEnd(), &encoded_method.access_flags,
                                 &bytes_read)) {
          success = false;
          break;
        }
        cur += bytes_read;
        if (0 != ReadUleb128Safe(cur, BufEnd(), &encoded_method.code_off,
                                 &bytes_read)) {
          success = false;
          break;
        }
        cur += bytes_read;
        class_data_item_->direct_methods.push_back(encoded_method);
      }
      if (!success) break;
      direct_methods_itor_ = class_data_item_->direct_methods.begin();

      class_data_item_->virtual_methods.reserve(virtual_methods_size);
      for (uint32_t i = 0; i < virtual_methods_size; i++) {
        DexEncodedMethod encoded_method;
        if (0 != ReadUleb128Safe(cur, BufEnd(), &encoded_method.method_idx_diff,
                                 &bytes_read)) {
          success = false;
          break;
        }
        cur += bytes_read;
        if (0 != ReadUleb128Safe(cur, BufEnd(), &encoded_method.access_flags,
                                 &bytes_read)) {
          success = false;
          break;
        }
        cur += bytes_read;
        if (0 != ReadUleb128Safe(cur, BufEnd(), &encoded_method.code_off,
                                 &bytes_read)) {
          success = false;
          break;
        }
        cur += bytes_read;
        class_data_item_->virtual_methods.push_back(encoded_method);
      }
      if (!success) break;
      virtual_methods_itor_ = class_data_item_->virtual_methods.begin();
    } catch (std::bad_alloc& e) {
      AAV_LOGE("DexFile::GetClass bad_alloc: %s", e.what());
      break;
    }

    current_class_idx_ =
        static_cast<int>(class_defs_itor_ - dex_format_->class_defs.begin());
    ++class_defs_itor_;
    ret = 0;
  } while (false);

  if (0 != ret) {
    class_data_item_.reset();

    if (dex_format_->class_defs.end() != class_defs_itor_) ++class_defs_itor_;
  }
  return ret;
}

// Return the next direct method's name and a DexCode over its instruction
// range. Encoded methods store method_idx as a diff from the previous entry in
// the list, so accumulate the diffs (in `key`) to recover the absolute
// method_ids index. The code_item header and instruction array are
// bounds-checked against the buffer before the range is handed to DexCode. Same
// 0 / -2 / -1 protocol as GetClass.
int DexFile::GetDirectMethod(std::string& method_name, std::string& proto_name,
                             DexCode& dex_code, uint32_t& key) {
  method_name.clear();
  proto_name.clear();
  int ret = -1;
  do {
    if (class_data_item_->direct_methods.end() == direct_methods_itor_) break;

    if (0 == key)
      key = direct_methods_itor_->method_idx_diff;
    else
      key += direct_methods_itor_->method_idx_diff;

    if (key >= dex_format_->method_ids.size()) {
      ret = -2;
      break;
    }

    uint32_t index = dex_format_->method_ids[key].name_idx;
    int result = GetStringString(index, method_name);
    if (0 != result) {
      ret = result;
      break;
    }

    if (direct_methods_itor_->code_off % 4 != 0 ||
        direct_methods_itor_->code_off <= 0x70 ||
        direct_methods_itor_->code_off >= target_size_) {
      ret = -2;
      break;
    }
    assert(0 == direct_methods_itor_->code_off % 4 &&
           direct_methods_itor_->code_off > 0x70 &&
           direct_methods_itor_->code_off < target_size_);
    DexCodeItem* item = reinterpret_cast<DexCodeItem*>(
        static_cast<char*>(dex_file_buf_) + direct_methods_itor_->code_off);
    size_t code_hdr = static_cast<size_t>(
        reinterpret_cast<char*>(&item->insns) - reinterpret_cast<char*>(item));
    if (static_cast<uint64_t>(direct_methods_itor_->code_off) + code_hdr >
        static_cast<uint64_t>(target_size_)) {
      ret = -2;
      break;
    }
    char* code_start = reinterpret_cast<char*>(&item->insns);
    uint64_t code_bytes =
        static_cast<uint64_t>(item->insns_size) * sizeof(uint16_t);
    if (static_cast<uint64_t>(direct_methods_itor_->code_off) + code_hdr +
            code_bytes >
        static_cast<uint64_t>(target_size_)) {
      ret = -2;
      break;
    }
    char* code_end = code_start + code_bytes;
    dex_code.Uninit();
    if (0 != dex_code.Init(this, code_start, code_end)) break;

    ++direct_methods_itor_;
    ret = 0;
  } while (false);

  if (0 != ret &&
      class_data_item_->direct_methods.end() != direct_methods_itor_)
    ++direct_methods_itor_;
  return ret;
}

// Mirrors GetDirectMethod for the class's virtual-method list.
int DexFile::GetVirtualMethod(std::string& method_name, std::string& proto_name,
                              DexCode& dex_code, uint32_t& key) {
  method_name.clear();
  proto_name.clear();
  int ret = -1;
  do {
    if (class_data_item_->virtual_methods.end() == virtual_methods_itor_) break;

    if (0 == key)
      key = virtual_methods_itor_->method_idx_diff;
    else
      key += virtual_methods_itor_->method_idx_diff;

    if (key >= dex_format_->method_ids.size()) {
      ret = -2;
      break;
    }

    uint32_t index = dex_format_->method_ids[key].name_idx;
    int result = GetStringString(index, method_name);
    if (0 != result) {
      ret = result;
      break;
    }

    if (virtual_methods_itor_->code_off % 4 != 0 ||
        virtual_methods_itor_->code_off <= 0x70 ||
        virtual_methods_itor_->code_off >= target_size_) {
      ret = -2;
      break;
    }
    DexCodeItem* item = reinterpret_cast<DexCodeItem*>(
        static_cast<char*>(dex_file_buf_) + virtual_methods_itor_->code_off);
    size_t code_hdr = static_cast<size_t>(
        reinterpret_cast<char*>(&item->insns) - reinterpret_cast<char*>(item));
    if (static_cast<uint64_t>(virtual_methods_itor_->code_off) + code_hdr >
        static_cast<uint64_t>(target_size_)) {
      ret = -2;
      break;
    }
    char* code_start = reinterpret_cast<char*>(&item->insns);
    uint64_t code_bytes =
        static_cast<uint64_t>(item->insns_size) * sizeof(uint16_t);
    if (static_cast<uint64_t>(virtual_methods_itor_->code_off) + code_hdr +
            code_bytes >
        static_cast<uint64_t>(target_size_)) {
      ret = -2;
      break;
    }
    char* code_end = code_start + code_bytes;
    dex_code.Uninit();
    if (0 != dex_code.Init(this, code_start, code_end)) break;

    ++virtual_methods_itor_;
    ret = 0;
  } while (false);

  if (0 != ret &&
      class_data_item_->virtual_methods.end() != virtual_methods_itor_)
    ++virtual_methods_itor_;
  return ret;
}

int DexFile::GetStringString(uint32_t index, std::string& str) {
  if (index >= dex_format_->string_ids.size()) return -2;

  if (dex_format_->string_ids[index].string_data_off <= 0x70 ||
      dex_format_->string_ids[index].string_data_off >= target_size_) {
    return -2;
  }
  assert(dex_format_->string_ids[index].string_data_off > 0x70 &&
         dex_format_->string_ids[index].string_data_off < target_size_);

  uint8_t* cur = reinterpret_cast<uint8_t*>(
      static_cast<char*>(dex_file_buf_) +
      dex_format_->string_ids[index].string_data_off);
  uint32_t utf16_size = 0;
  int bytes_read = 0;
  if (0 != ReadUleb128Safe(cur, BufEnd(), &utf16_size, &bytes_read)) return -2;
  const char* str_begin = reinterpret_cast<const char*>(cur) + bytes_read;
  const char* tail = reinterpret_cast<const char*>(BufEnd());
  if (str_begin > tail) return -2;
  if (nullptr == memchr(str_begin, 0, static_cast<size_t>(tail - str_begin)))
    return -2;
  try {
    str = str_begin;
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexFile::GetStringString bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

int DexFile::GetTypeString(uint32_t index, std::string& str) {
  if (index >= dex_format_->type_ids.size()) return -2;
  return GetStringString(dex_format_->type_ids[index].descriptor_idx, str);
}

int DexFile::GetProtoInfo(uint32_t index, ProtoInfo& proto_info) {
  if (index >= dex_format_->proto_ids.size()) return -2;

  int result = GetStringString(dex_format_->proto_ids[index].shorty_idx,
                               proto_info.shorty);
  if (0 != result) return result;
  result = GetTypeString(dex_format_->proto_ids[index].return_type_idx,
                         proto_info.return_type);
  if (0 != result) return result;

  // parameters_off == 0 means "no parameters" per the DEX spec.
  uint32_t parameters_off = dex_format_->proto_ids[index].parameters_off;
  if (0 == parameters_off) return 0;

  // The type_list header (u32 count) must lie past the header and inside buf.
  if (parameters_off < sizeof(DexHeader) ||
      static_cast<uint64_t>(parameters_off) + sizeof(uint32_t) > target_size_) {
    return -2;
  }
  const uint8_t* base = static_cast<const uint8_t*>(dex_file_buf_);
  uint32_t size = 0;
  memcpy(&size, base + parameters_off, sizeof(size));

  // Each entry is a u16 type index; the whole list must fit in the buffer.
  uint64_t list_off = static_cast<uint64_t>(parameters_off) + sizeof(uint32_t);
  if (list_off + static_cast<uint64_t>(size) * sizeof(uint16_t) >
      target_size_) {
    return -2;
  }

  try {
    std::string str;
    proto_info.parameters.reserve(size);
    for (uint32_t i = 0; i < size; i++) {
      uint16_t type_index = 0;
      memcpy(&type_index,
             base + list_off + static_cast<uint64_t>(i) * sizeof(uint16_t),
             sizeof(type_index));
      result = GetTypeString(type_index, str);
      if (0 != result) return result;
      proto_info.parameters.push_back(str);
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexFile::GetProtoInfo bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

int DexFile::GetFieldInfo(uint32_t index, FieldInfo& field_info) {
  if (index >= dex_format_->field_ids.size()) return -2;

  int result = GetTypeString(dex_format_->field_ids[index].class_idx,
                             field_info.class_str);
  if (0 != result) return result;
  result =
      GetTypeString(dex_format_->field_ids[index].type_idx, field_info.type);
  if (0 != result) return result;
  result =
      GetStringString(dex_format_->field_ids[index].name_idx, field_info.name);
  if (0 != result) return result;
  return 0;
}

int DexFile::GetMethodInfo(uint32_t index, MethodInfo& method_info) {
  if (index >= dex_format_->method_ids.size()) return -2;

  int result = GetTypeString(dex_format_->method_ids[index].class_idx,
                             method_info.class_str);
  if (0 != result) return result;
  // A proto lookup miss is tolerated: proceed with best-effort method info.
  GetProtoInfo(dex_format_->method_ids[index].proto_idx,
               method_info.proto_info);
  result = GetStringString(dex_format_->method_ids[index].name_idx,
                           method_info.name);
  if (0 != result) return result;
  return 0;
}

int DexFile::GetClassInfo(uint32_t index, ClassInfo& class_info) {
  if (index >= dex_format_->class_defs.size()) return -2;

  int result = GetTypeString(dex_format_->class_defs[index].class_idx,
                             class_info.class_str);
  if (0 != result) return result;

  // superclass_idx may be NO_INDEX (0xffffffff) for java/lang/Object; skip the
  // lookup when out of range and leave super_class empty rather than failing.
  if (dex_format_->class_defs[index].superclass_idx <
      dex_format_->type_ids.size()) {
    result = GetTypeString(dex_format_->class_defs[index].superclass_idx,
                           class_info.super_class);
    if (0 != result) return result;
  }

  // source_file_idx may be NO_INDEX (no source file); skip the lookup when it
  // is out of range and leave class_info.source_file empty.
  if (dex_format_->class_defs[index].source_file_idx <
      dex_format_->string_ids.size()) {
    GetStringString(dex_format_->class_defs[index].source_file_idx,
                    class_info.source_file);
  }
  return 0;
}

int DexFile::GetCurrentClassInfo(ClassInfo& class_info) {
  if (current_class_idx_ < 0) return -1;
  return GetClassInfo(static_cast<uint32_t>(current_class_idx_), class_info);
}

int DexFile::GetCurrentClassFields(std::vector<FieldInfo>& fields) {
  if (nullptr == class_data_item_) return -1;

  // Encoded-field indices are stored as diffs within each list; accumulate them
  // per list to recover the absolute field_ids index.
  uint32_t idx = 0;
  bool first = true;
  for (const DexEncodedField& ef : class_data_item_->static_fields) {
    idx = first ? ef.field_idx_diff : idx + ef.field_idx_diff;
    first = false;
    FieldInfo fi;
    if (0 == GetFieldInfo(idx, fi)) {
      fi.is_static = true;
      fields.push_back(fi);
    }
  }
  idx = 0;
  first = true;
  for (const DexEncodedField& ef : class_data_item_->instance_fields) {
    idx = first ? ef.field_idx_diff : idx + ef.field_idx_diff;
    first = false;
    FieldInfo fi;
    if (0 == GetFieldInfo(idx, fi)) {
      fi.is_static = false;
      fields.push_back(fi);
    }
  }
  return 0;
}

int DexFile::ParseHeader() {
  DexHeader* header_item = &dex_format_->header;
  assert(0x70 == sizeof(DexHeader));
  // The buffer must be at least a full header; a shorter (attacker-supplied)
  // file would otherwise cause an over-read in the memcpy below.
  if (target_size_ < sizeof(DexHeader)) return -1;
  memcpy(header_item, dex_file_buf_, sizeof(DexHeader));
  if (!IsSupportedDexMagic(header_item->magic)) return -1;
  if (header_item->file_size != target_size_) return -1;
  if (0x70 != header_item->header_size) return -1;

  if (ENDIAN_CONSTANT == header_item->endian_tag)
    little_endian_tag_ = true;
  else if (REVERSE_ENDIAN_CONSTANT == header_item->endian_tag)
    little_endian_tag_ = false;
  else
    return -1;

  return 0;
}

int DexFile::ParseStringIDs() {
  DexHeader* header_item = &dex_format_->header;
  uint32_t size = header_item->string_ids_size;
  if (size > kMaxDexItemCount) return -1;
  if (!RegionOk(header_item->string_ids_off, size, sizeof(DexStringId)))
    return -1;
  max_string_id_ = size - 1;

  try {
    dex_format_->string_ids.reserve(size);
    DexStringId* item = reinterpret_cast<DexStringId*>(
        static_cast<char*>(dex_file_buf_) + header_item->string_ids_off);
    for (int i = 0; i < size; i++) {
      dex_format_->string_ids.push_back(item[i]);
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexFile::ParseStringIDs bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

int DexFile::ParseTypeIDs() {
  DexHeader* header_item = &dex_format_->header;
  uint32_t size = header_item->type_ids_size;
  if (size > kMaxDexItemCount) return -1;
  if (!RegionOk(header_item->type_ids_off, size, sizeof(DexTypeId))) return -1;
  max_type_id_ = size - 1;

  try {
    dex_format_->type_ids.reserve(size);
    DexTypeId* item = reinterpret_cast<DexTypeId*>(
        static_cast<char*>(dex_file_buf_) + header_item->type_ids_off);
    for (int i = 0; i < size; i++) {
      dex_format_->type_ids.push_back(item[i]);
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexFile::ParseTypeIDs bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

int DexFile::ParseProtoIDs() {
  DexHeader* header_item = &dex_format_->header;
  uint32_t size = header_item->proto_ids_size;
  if (size > kMaxDexItemCount) return -1;
  if (!RegionOk(header_item->proto_ids_off, size, sizeof(DexProtoId)))
    return -1;
  max_proto_id_ = size - 1;

  try {
    dex_format_->proto_ids.reserve(size);
    DexProtoId* item = reinterpret_cast<DexProtoId*>(
        static_cast<char*>(dex_file_buf_) + header_item->proto_ids_off);
    for (int i = 0; i < size; i++) {
      // assert(item[i].parameters_off != 0);
      dex_format_->proto_ids.push_back(item[i]);
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexFile::ParseProtoIDs bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

int DexFile::ParseFieldIDs() {
  DexHeader* header_item = &dex_format_->header;
  uint32_t size = header_item->field_ids_size;
  if (size > kMaxDexItemCount) return -1;
  if (!RegionOk(header_item->field_ids_off, size, sizeof(DexFieldId)))
    return -1;
  max_field_id_ = size - 1;

  try {
    dex_format_->field_ids.reserve(size);
    DexFieldId* item = reinterpret_cast<DexFieldId*>(
        static_cast<char*>(dex_file_buf_) + header_item->field_ids_off);
    for (int i = 0; i < size; i++) {
      dex_format_->field_ids.push_back(item[i]);
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexFile::ParseFieldIDs bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

int DexFile::ParseMethodIDs() {
  DexHeader* header_item = &dex_format_->header;
  uint32_t size = header_item->method_ids_size;
  if (size > kMaxDexItemCount) return -1;
  if (!RegionOk(header_item->method_ids_off, size, sizeof(DexMethodId)))
    return -1;
  max_method_id_ = size - 1;

  try {
    dex_format_->method_ids.reserve(size);
    DexMethodId* item = reinterpret_cast<DexMethodId*>(
        static_cast<char*>(dex_file_buf_) + header_item->method_ids_off);
    for (int i = 0; i < size; i++) {
      dex_format_->method_ids.push_back(item[i]);
    }
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexFile::ParseMethodIDs bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

int DexFile::ParseClassDefs() {
  DexHeader* header_item = &dex_format_->header;
  uint32_t size = header_item->class_defs_size;
  if (size > kMaxDexItemCount) return -1;
  if (!RegionOk(header_item->class_defs_off, size, sizeof(DexClassDef)))
    return -1;
  max_class_def_id_ = size - 1;

  try {
    dex_format_->class_defs.reserve(size);
    DexClassDef* item = reinterpret_cast<DexClassDef*>(
        static_cast<char*>(dex_file_buf_) + header_item->class_defs_off);
    for (int i = 0; i < size; i++) {
      dex_format_->class_defs.push_back(item[i]);
    }
    class_defs_itor_ = dex_format_->class_defs.begin();
  } catch (std::bad_alloc& e) {
    AAV_LOGE("DexFile::ParseClassDefs bad_alloc: %s", e.what());
    return -1;
  }
  return 0;
}

}  // namespace aav
