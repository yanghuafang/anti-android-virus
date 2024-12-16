#ifndef AAV_DEX_DEX_FORMAT_H_
#define AAV_DEX_DEX_FORMAT_H_

#include <stdint.h>

#include <list>
#include <vector>

namespace aav {

// Type names follow AOSP libdex's PascalCase Dex* convention; field names and
// the comments keep the on-disk DEX-spec vocabulary (e.g. string_id_item) so
// each struct still maps 1:1 to the published "Dalvik Executable format" doc.

#pragma pack(push, 4)

struct DexHeader {
  uint8_t magic[8];  // DEX_FILE_MAGIC
  uint32_t checksum;
  uint8_t signature[20];
  uint32_t file_size;
  uint32_t header_size;  // 0x70
  uint32_t endian_tag;   // ENDIAN_CONSTANT
  uint32_t link_size;
  uint32_t link_off;
  uint32_t map_off;
  uint32_t string_ids_size;
  uint32_t string_ids_off;
  uint32_t type_ids_size;
  uint32_t type_ids_off;
  uint32_t proto_ids_size;
  uint32_t proto_ids_off;
  uint32_t field_ids_size;
  uint32_t field_ids_off;
  uint32_t method_ids_size;
  uint32_t method_ids_off;
  uint32_t class_defs_size;
  uint32_t class_defs_off;
  uint32_t data_size;
  uint32_t data_off;
};

struct DexStringId {
  uint32_t string_data_off;  // points to string_data_item
};

struct DexTypeId {
  uint32_t descriptor_idx;  // index of string_id_item list
};

struct DexProtoId {
  uint32_t shorty_idx;  // index of string_id_item list  //method declaration:
                        // return type + parameters type
  uint32_t return_type_idx;  // index of type_id_item list
  uint32_t parameters_off;   // points to type_list
};

struct DexFieldId {
  uint16_t class_idx;  // index of type_id_item list //the class in which the
                       // field exists
  uint16_t type_idx;   // index of type_id_item list
  uint32_t name_idx;   // index of string_id_item list
};

struct DexMethodId {
  uint16_t class_idx;  // index of type_id_item list //the class in which the
                       // method exists
  uint16_t proto_idx;  // index of proto_id_item list
  uint32_t name_idx;   // index of string_id_item list
};

struct DexClassDef {
  uint32_t class_idx;          // index of type_id_item list
  uint32_t access_flags;       // ACCESS_FLAGS
  uint32_t superclass_idx;     // index of type_id_item list
  uint32_t interfaces_off;     // points to array of type_id_item (type_ids)
  uint32_t source_file_idx;    // index of string_id_item_list
  uint32_t annotations_off;    // points to array of annotations_directory_item
  uint32_t class_data_off;     // points to array of class_data_item
  uint32_t statis_values_off;  // points to array of encoded_array_item
};

struct DexFormat {
 public:
  DexHeader header;
  std::vector<DexStringId> string_ids;
  std::vector<DexTypeId> type_ids;
  std::vector<DexProtoId> proto_ids;
  std::vector<DexFieldId> field_ids;
  std::vector<DexMethodId> method_ids;
  std::vector<DexClassDef> class_defs;
  std::vector<uint8_t> data;
  std::vector<uint8_t> link_data;
};

////////////////////////////////////////////////////////////////
enum DexItemType {
  kTypeHeaderItem = 0x0000,
  kTypeStringIdItem,
  kTypeTypeIdItem,
  kTypeProtoIdItem,
  kTypeFieldIdItem,
  kTypeMethodIdItem,
  kTypeClassDefItem,

  kTypeMapList = 0x1000,
  kTypeTypeList,
  kTypeAnnotationSetRefList,
  kTypeAnnotationSetItem,

  kTypeClassDataItem = 0x2000,
  kTypeCodeItem,
  kTypeStringDataItem,
  kTypeDebugInfoItem,
  kTypeAnnotationItem,
  kTypeEncodedArrayItem,
  kTypeAnnotationsDirectoryItem,
};

struct DexMapItem {
  uint16_t type;  // DEX_ITEM_TYPE
  uint16_t unused;
  uint32_t size;
  uint32_t offset;
};

struct DexMapList {
  uint32_t size;  // count of map_item
  std::vector<DexMapItem> list;
};
////////////////////////////////////////////////////////////////

enum DexAccessFlags {
  kAccPublic = 0x1,
  kAccPrivate = 0x2,
  kAccProtected = 0x4,
  kAccStatic = 0x8,
  kAccFinal = 0x10,
  kAccSynchronized = 0x20,
  kAccVolatile = 0x40,
  kAccBridge = 0x40,
  kAccTransient = 0x80,
  kAccVarargs = 0x80,
  kAccNative = 0x100,
  kAccInterface = 0x200,
  kAccAbstract = 0x400,
  kAccStrict = 0x800,
  kAccSynthetic = 0x1000,
  kAccAnnotation = 0x2000,
  kAccEnum = 0x4000,
  kAccUnused = 0x8000,
  kAccConstructor = 0x10000,
  kAccDeclared = 0x20000,
  kSynchronized,
};

////////////////////////////////////////////////////////////////
#pragma pack(push, 1)

struct DexStringData {
  uint32_t utf16_size;  // uleb128 //size of this string, in UTF-16 code units
  uint8_t data[1];
};

#pragma pack(pop)
////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////
struct DexTypeItem {
  uint16_t type_idx;  // index of type_id_item list
};

struct DexTypeList {
  uint32_t size;
  std::vector<DexTypeItem> list;
};
////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////
struct DexTry {
  uint32_t start_addr;  // start address of the block of code covered by this
                        // entry. The address is a count of 16-bit code units to
                        // the start of the first covered instruction.
  uint16_t insn_count;  // number of 16-bit code units covered by this entry.
                        // The last code unit covered(inclusive) is start_addr +
                        // insn_count - 1.
  uint16_t handler_off;  // offset in bytes in encoded_catch_handler_list
};

struct DexEncodedTypeAddrPair {
  uint32_t type_idx;  // uleb128 //index of type_ids
  uint32_t addr;      // uleb128 //
};

struct DexEncodedCatchHandler {
  int32_t size;  // sleb128
  std::vector<DexEncodedTypeAddrPair> handlers;
  uint32_t
      catch_all_addr;  // uleb128 //bytecode address of the catch-all handler
};

struct DexEncodedCatchHandlerList {
  uint32_t size;  // uleb128
  std::vector<DexEncodedCatchHandler> list;
};

struct DexCodeItem {
  uint16_t registers_size;
  uint16_t ins_size;
  uint16_t outs_size;
  uint16_t tries_size;
  uint32_t debug_info_off;  // points to array of debug_info_item
  uint32_t insns_size;  // size of the instructions list, in 16-bit code units
  std::vector<uint16_t> insns;  // actual array of bytecode
  uint16_t padding;             // optional
  std::vector<DexTry> tries;    // optional
  DexEncodedCatchHandlerList handlers;
};

#pragma pack(push, 1)

struct DexEncodedField {
  uint32_t field_idx_diff;  // uleb128 //diff index of field_ids
  uint32_t access_flags;    // uleb128
};

struct DexEncodedMethod {
  uint32_t method_idx_diff;  // uleb128 //diff index of method_ids
  uint32_t access_flags;     // uleb128
  uint32_t code_off;         // uleb128 //points to array of code_item
};

struct DexClassData {
  uint32_t static_fields_size;                 // uleb128
  uint32_t instance_fields_size;               // uleb128
  uint32_t direct_methods_size;                // uleb128
  uint32_t virtual_methods_size;               // uleb128
  std::vector<DexEncodedField> static_fields;  // count is static_fields_size
  std::vector<DexEncodedField>
      instance_fields;  // count is instance_fields_size
  std::vector<DexEncodedMethod> direct_methods;  // count is direct_methods_size
  std::vector<DexEncodedMethod>
      virtual_methods;  // count is virtual_methods_size
};

#pragma pack(pop)
////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////
enum DexValueType {
  kValueByte = 0x00,
  kValueShort = 0x02,
  kValueChar = 0x03,
  kValueInt = 0x04,
  kValueLong = 0x06,
  kValueFloat = 0x10,
  kValueDouble = 0x11,
  kValueString = 0x17,
  kValueType = 0x18,
  kValueField = 0x19,
  kValueMethod = 0x1a,
  kValueEnum = 0x1b,
  kValueArray = 0x1c,
  kValueAnnotation = 0x1d,
  kValueNull = 0x1e,
  kValueBoolean = 0x1f,
};

#pragma pack(push, 1)

struct DexEncodedValue {
  uint8_t value_arg_type;  //(value_arg << 5) | value_type
  std::vector<uint8_t> value;
};

struct DexEncodedArray {
  uint32_t size;  // uleb128
  std::vector<DexEncodedValue> values;
};

struct DexEncodedArrayItem {
  DexEncodedArray value;
};

#pragma pack(pop)
////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////
enum DexVisibility {
  kVisibilityBuild = 0x0,
  kVisibilityRuntime = 0x1,
  kVisibilitySystem = 0x2,
};

#pragma pack(push, 1)

struct DexAnnotationElement {
  uint32_t name_idx;  // uleb128 //index of string_ids
  DexEncodedValue value;
};

struct DexEncodedAnnotation {
  uint32_t type_idx;                           // uleb128
  uint32_t size;                               // uleb128
  std::vector<DexAnnotationElement> elements;  // count is size
};

struct DexAnnotationItem {
  uint8_t visibility;  // VISIBILITY
  DexEncodedAnnotation annotation;
};

#pragma pack(pop)

struct DexAnnotationOffItem {
  uint32_t annotation_off;  // offset from the start of the file to an
                            // annotation. //points to anotation_item
};

struct DexAnnotationSetItem {
  uint32_t size;
  std::vector<DexAnnotationOffItem> entries;
};

struct DexAnnotationSetRefItem {
  uint32_t annotations_off;  // offset from the start of the file to the
                             // referenced annotation
};

struct DexAnnotationSetRefList {
  uint32_t size;
  std::vector<DexAnnotationSetRefItem> list;
};

struct DexFieldAnnotation {
  uint32_t field_idx;        // index of field_ids
  uint32_t annotations_off;  // offset from the start of the file to the array
                             // of annotations for the field. //points to
                             // annotation_set_item
};

struct DexMethodAnnotation {
  uint32_t method_idx;       // index of method_ids
  uint32_t annotations_off;  // offset from the start of the file to the array
                             // of annotations for the method. //points to
                             // annotation_set_item
};

struct DexParameterAnnotation {
  uint32_t method_idx;       // index of method_ids
  uint32_t annotations_off;  // offset from the start of the file to the array
                             // of annotations for the method parameters.
                             // //points to annotation_set_ref_list
};

struct DexAnnotationsDirectory {
  uint32_t class_annotations_off;
  uint32_t fields_size;
  uint32_t annotated_methods_size;
  uint32_t annotated_parameters_size;
  std::vector<DexFieldAnnotation>
      field_annotations;  // count is fields_size  //optional
  std::vector<DexMethodAnnotation>
      method_annotations;  // count is annotated_methods_size //optional
  std::vector<DexParameterAnnotation>
      parameter_annotations;  // count is annotated_parameters_size //optional
};
////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////
#pragma pack(push, 1)

struct DexPackedSwitchPayload {
  uint16_t ident;  // 0x0100
  uint16_t size;
  int32_t first_key;
  int32_t targets[1];
};

struct DexSparseSwitchPayload {
  uint16_t ident;  // 0x0200
  uint16_t size;
  int32_t keys[1];
  int32_t targets[1];
};

struct DexFillArrayDataPayload {
  uint16_t ident;  // 0x0300
  uint16_t element_width;
  uint32_t size;
  uint8_t data[1];
};

#pragma pack(pop)
////////////////////////////////////////////////////////////////

#pragma pack(pop)

}  // namespace aav

#endif
