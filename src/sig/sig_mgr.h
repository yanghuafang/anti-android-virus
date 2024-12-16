#ifndef AAV_SIG_SIG_MGR_H_
#define AAV_SIG_SIG_MGR_H_

#include <string>
#include <vector>

#include "aav/sig_mgr_interface.h"
#include "sig_db_structure.h"

namespace aav {
struct AdInfoNode {
  uint32_t sig_id;
  void* ad_info;
};

class SigMgr : public ISigMgr {
 public:
  SigMgr();
  ~SigMgr();

  int Init(void* context);
  int Uninit();
  int LoadSigs(const char* path, const LoadFormatConfig* config);
  int UnloadSigs();
  int UpdateSigs(const char* dir);
  int SigVersion();
  int GetData(SigFormat format, SigItem** item);
  int GetMalwareName(int sig_id, char* name_buf, int name_buf_size);
  // int getADInfo(int sig_id, AD_INFO** adInfo);
  int GetAdInfo(int sig_id, void** ad_info);

 private:
  int CheckAndLoadSigs(const char* path, const LoadFormatConfig* config,
                       bool updated = false);
  int DealWithSection(SigItem* sig_item);
  int LoadBinaryFile(const std::string& filename, std::string& contents);
  int BuildData(SigItem*, std::vector<std::string>& data);
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
