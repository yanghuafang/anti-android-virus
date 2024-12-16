#ifndef AAV_DEX_DEX_FILE_H_
#define AAV_DEX_DEX_FILE_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "dex_format.h"

namespace aav {

constexpr uint32_t kMaxDexItemCount = 65536 * 10;

class ITarget;
class DexCode;

struct ProtoInfo {
  std::string shorty;
  std::string return_type;
  std::vector<std::string> parameters;
};

struct FieldInfo {
  std::string class_str;
  std::string type;
  std::string name;
  bool is_static = false;
};

struct MethodInfo {
  std::string class_str;
  ProtoInfo proto_info;
  std::string name;
};

struct ClassInfo {
  std::string class_str;
  std::string super_class;
  std::string source_file;
};

class DexFile {
 public:
  DexFile();
  ~DexFile();

  int Init(ITarget* target);
  int Uninit();

  int GetClass(std::string& class_name);
  int GetDirectMethod(std::string& method_name, std::string& proto_name,
                      DexCode& dex_code, uint32_t& key);
  int GetVirtualMethod(std::string& method_name, std::string& proto_name,
                       DexCode& dex_code, uint32_t& key);

  int GetStringString(uint32_t index, std::string& str);
  int GetTypeString(uint32_t index, std::string& str);
  int GetProtoInfo(uint32_t index, ProtoInfo& proto_info);
  int GetFieldInfo(uint32_t index, FieldInfo& field_info);
  int GetMethodInfo(uint32_t index, MethodInfo& method_info);
  int GetClassInfo(uint32_t index, ClassInfo& class_info);

  // Info for the class most recently returned by GetClass(); for --analysis.
  int GetCurrentClassInfo(ClassInfo& class_info);
  int GetCurrentClassFields(std::vector<FieldInfo>& fields);

 private:
  int ParseHeader();
  int ParseStringIDs();
  int ParseTypeIDs();
  int ParseProtoIDs();
  int ParseFieldIDs();
  int ParseMethodIDs();
  int ParseClassDefs();

  const uint8_t* BufEnd() const;
  bool RegionOk(uint32_t off, uint32_t count, uint32_t item_size) const;

 private:
  std::unique_ptr<DexFormat> dex_format_;
  std::unique_ptr<DexClassData> class_data_item_;

  int max_string_id_;
  int max_type_id_;
  int max_proto_id_;
  int max_field_id_;
  int max_method_id_;
  int max_class_def_id_;
  int current_class_idx_;  // index of the class last returned by GetClass()

  void* dex_file_buf_;
  uint32_t target_size_;
  bool little_endian_tag_;

  std::vector<DexClassDef>::iterator class_defs_itor_;
  std::vector<DexEncodedMethod>::iterator direct_methods_itor_;
  std::vector<DexEncodedMethod>::iterator virtual_methods_itor_;
};

}  // namespace aav

#endif
