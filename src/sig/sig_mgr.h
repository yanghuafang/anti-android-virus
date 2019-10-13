#ifndef AAV_SIG_SIG_MGR_H_
#define AAV_SIG_SIG_MGR_H_

#include <string>
#include <vector>

#include "aav/sig_mgr_interface.h"
#include "sig/sig_db_structure.h"

namespace aav {
struct AdInfoNode {
  uint32_t sig_id;
  void* ad_info;
};

class SigMgr final : public ISigMgr {
 public:
  SigMgr();
  ~SigMgr() override;

  int Init(void* context) override;
  int Uninit() override;
  int LoadSigs(const char* path, const LoadFormatConfig* config) override;
  int UnloadSigs() override;
  int UpdateSigs(const char* dir) override;
  int SigVersion() override;
  int GetData(SigFormat format, SigItem** item) override;
  int GetMalwareName(int sig_id, char* name_buf, int name_buf_size) override;
  // int getADInfo(int sig_id, AD_INFO** adInfo);
  int GetAdInfo(int sig_id, void** ad_info) override;

 private:
  int CheckAndLoadSigs(const char* path, const LoadFormatConfig* config,
                       bool updated = false);
  int DealWithSection(SigItem* sig_item);
  static int LoadBinaryFile(const std::string& filename, std::string& contents);
  static int BuildData(SigItem* /*sig_item*/, std::vector<std::string>& data);
  int BuildDataFamily(SigItem* sig_item);
  int BuildDataAdinfo(SigItem* sig_item);

  int file_buffer_len_;
  unsigned char* file_buffer_ptr_;
  char* sig_file_path_;
  SigHeader sig_header_;
  std::vector<int> family_id_vector_;
  std::vector<std::string> malware_type_vector_;
  std::vector<std::string> platform_vector_;
  std::vector<std::string> file_format_vector_;
  std::vector<std::string> variant_vector_;
  std::vector<std::string> family_name_vector_;
  std::vector<AdInfoNode> ad_info_vector_;
  std::vector<SigItem*> section_vector_;
};

}  // namespace aav

#endif
