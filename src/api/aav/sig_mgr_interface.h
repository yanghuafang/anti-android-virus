#ifndef AAV_SIG_MGR_INTERFACE_H_
#define AAV_SIG_MGR_INTERFACE_H_

#include <stdint.h>

#include "aav/object_interface.h"
#include "aav/sig_format.h"

namespace aav {

struct LoadFormatConfig;
struct SigItem;
struct AdInfo;

class ISigMgr : public IObject {
 public:
  virtual int Init(void* context) = 0;
  virtual int Uninit() = 0;
  virtual int LoadSigs(const char* path, const LoadFormatConfig* config) = 0;
  virtual int UnloadSigs() = 0;
  virtual int UpdateSigs(const char* dir) = 0;
  virtual int SigVersion() = 0;
  virtual int GetData(SigFormat format, SigItem** item) = 0;
  virtual int GetMalwareName(int sig_id, char* name_buf, int name_buf_size) = 0;
  virtual int GetAdInfo(int sig_id, void** ad_info) = 0;
};

}  // namespace aav

#endif
