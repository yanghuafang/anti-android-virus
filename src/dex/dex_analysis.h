#ifndef AAV_DEX_DEX_ANALYSIS_H_
#define AAV_DEX_DEX_ANALYSIS_H_

#include <stdint.h>

#include <string>
#include <vector>

namespace aav {

// A declared field of a class. `type` is the raw DEX type descriptor (e.g.
// "Landroid/os/Bundle;").
struct DexAnalysisField {
  std::string name;
  std::string type;
  bool is_static = false;
};

// Per-method feature record produced when analysis is enabled. Intended to help
// a human author signatures: the CRCs below are exactly what the opcode/operand
// and logic signatures are built from, and `strings` shows the const-strings
// that feed the operand CRC. `return_type`/`params` are raw DEX type
// descriptors and disambiguate overloaded methods.
struct DexAnalysisMethod {
  std::string method_name;
  std::string return_type;
  std::vector<std::string> params;
  bool is_direct = false;  // direct (static/private/ctor) vs virtual
  bool known = false;      // matched an existing signature during this scan
  bool has_opcode_crc = false;
  uint32_t opcode_crc = 0;
  bool has_operand_crc = false;
  uint32_t operand_crc = 0;
  std::vector<std::string> strings;
};

// Per-class record: the class, its declared fields, and its methods.
// `class_path` is regularized (dotted, lower-case) to match path signatures;
// `super_class` is a raw DEX type descriptor and may be empty (e.g. for
// java/lang/Object).
struct DexAnalysisClass {
  std::string class_path;
  std::string super_class;
  std::string source_file;
  std::vector<DexAnalysisField> fields;
  std::vector<DexAnalysisMethod> methods;
};

struct DexAnalysisReport {
  std::vector<DexAnalysisClass> classes;
};

// Runtime toggle, off by default so real-time scanning (e.g. on Android) stays
// fast. The DEX scanner records into the report only while this is enabled.
void SetDexAnalysisEnabled(bool enabled);
bool IsDexAnalysisEnabled();

// Report from the most recent scan; cleared at the start of each scan when
// analysis is enabled, and valid until the next scan.
DexAnalysisReport& MutableDexAnalysisReport();
const DexAnalysisReport& GetDexAnalysisReport();

}  // namespace aav

#endif
