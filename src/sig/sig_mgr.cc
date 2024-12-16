/*
 * signature load - called by framework to load signature database
 */

#include "sig_mgr.h"

#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#include <vector>

#include "aav/sig_format.h"
#include "blowfish.h"
#include "common_define.h"
#include "file_uncompress.h"
#include "log.h"
#include "malware_name.h"
#include "sig_db_structure.h"

namespace aav {

static constexpr uint32_t AlignSize4(uint32_t s) { return (s + 3) & ~3u; }

#define return_error(msg, ret)          \
  do {                                  \
    AAV_LOGE("SigMgr: %s failed", msg); \
    return (ret);                       \
  } while (0)

SigMgr::SigMgr() { Init(nullptr); }

SigMgr::~SigMgr() { Uninit(); }

int SigMgr::Init(void* context) {
  file_buffer_ptr_ = nullptr;
  sig_file_path_ = nullptr;
  file_buffer_len_ = 0;
  memset(&sig_header_, 0, sizeof(SigHeader));

  return kAdSuccess;
}

int SigMgr::Uninit() {
  UnloadSigs();
  memset(&sig_header_, 0, sizeof(SigHeader));
  if (sig_file_path_ != nullptr) {
    free(sig_file_path_);
    sig_file_path_ = nullptr;
  }

  return kAdSuccess;
}

/* Reads a file into memory. */
int SigMgr::LoadBinaryFile(const std::string& filename, std::string& contents) {
  // Open the gzip file in binary mode
  FILE* f = fopen(filename.c_str(), "rb");
  if (f == nullptr) return kAdError;

  // Clear existing bytes in output vector
  contents.clear();

  // Read all the bytes in the file
  int c = fgetc(f);
  while (c != EOF) {
    contents += static_cast<char>(c);
    c = fgetc(f);
  }
  fclose(f);
  return kAdSuccess;
}

int SigMgr::LoadSigs(const char* path, const LoadFormatConfig* config) {
  return CheckAndLoadSigs(path, config, false);
}

int SigMgr::CheckAndLoadSigs(const char* path, const LoadFormatConfig* config,
                             bool updated) {
  int offset = 0;
  int sig_header_len = sizeof(SigHeader);
  int sig_section_header_len = sizeof(SigSectionHeader);
  SigHeader tmp_sig_header;
  memset(&tmp_sig_header, 0, sig_header_len);

  // load file
  std::string file_data;
  std::string filname(path);
  if (LoadBinaryFile(filname, file_data) == kAdError) {
    return_error("loadBinaryFile", kAdSigLoad);
  }

  // blowfish decrypt
  char key[] = "aav-dex-malware-signature-db-v1";
  Blowfish blowfish;
  std::string decrypted;
  blowfish.SetKey(key);
  blowfish.Decrypt(&decrypted, file_data);
  if (decrypted.length() == 0) {
    return_error("Blowfish", kAdSigEncrypt);
  }

  // uncompress
  std::string uncompress_data;
  if (GzipInflate(decrypted, uncompress_data) == false) {
    return_error("uncompress", kAdSigUncompress);
  }

  file_buffer_len_ = uncompress_data.length();
  if (file_buffer_len_ <= sig_header_len) {
    return_error("uncompress", kAdSigUncompress);
  }
  file_buffer_ptr_ = static_cast<unsigned char*>(malloc(file_buffer_len_));
  if (nullptr == file_buffer_ptr_) {
    return_error("malloc", kAdSigLoad);
  }
  memset(file_buffer_ptr_, '\0', file_buffer_len_);
  memcpy(file_buffer_ptr_, uncompress_data.c_str(), file_buffer_len_);

  // get sig file header
  memcpy(&tmp_sig_header, file_buffer_ptr_, sig_header_len);
  AAV_LOGD("sig DB magic=0x%x version=%u", tmp_sig_header.magic,
           tmp_sig_header.version);
  if (tmp_sig_header.magic != kSigMagic) {
    return_error("magic", kAdSigMagic);
  }

  offset = sig_header_len;
  unsigned long crc =
      Crc32Buffer((file_buffer_ptr_ + offset), file_buffer_len_ - offset);
  if (tmp_sig_header.crc != crc) {
    return_error("crc", kAdSigCrc);
  }

  if (updated && tmp_sig_header.version <= sig_header_.version) {
    return_error("version", kAdSigLowVersion);
  }

  // get sig section
  while (offset < file_buffer_len_) {
    // A full section header must be present in the remaining bytes.
    if (file_buffer_len_ - offset < sig_section_header_len) {
      return_error("section header truncated", kAdSigLoad);
    }
    SigSectionHeader section_header;
    memcpy(&section_header, file_buffer_ptr_ + offset, sig_section_header_len);
    offset += sig_section_header_len;

    // The section payload must fit within the remaining buffer.
    if (section_header.packed_size >
        static_cast<uint32_t>(file_buffer_len_ - offset)) {
      return_error("section payload truncated", kAdSigLoad);
    }

    SigItem* sig_item = static_cast<SigItem*>(malloc(sizeof(SigItem)));
    if (nullptr == sig_item) {
      return_error("malloc", kAdSigLoad);
    }
    memset(sig_item, '\0', sizeof(SigItem));
    sig_item->format = section_header.format;
    sig_item->buf_size = section_header.packed_size;
    sig_item->sig_count = section_header.sig_count;
    sig_item->buf = reinterpret_cast<void*>(file_buffer_ptr_ + offset);
    AAV_LOGD("sig section format=%u size=%u count=%u",
             static_cast<unsigned>(sig_item->format),
             static_cast<unsigned>(sig_item->buf_size),
             static_cast<unsigned>(sig_item->sig_count));
    section_vector_.push_back(sig_item);

    if (kAdSuccess != DealWithSection(sig_item)) {
      return_error("section parse", kAdSigLoad);
    }
    offset += sig_item->buf_size;
  }

  int path_len = strlen(path);
  sig_file_path_ = static_cast<char*>(malloc(path_len + 1));
  memset(sig_file_path_, '\0', path_len + 1);
  strncpy(sig_file_path_, path, path_len);
  memcpy(&sig_header_, &tmp_sig_header, sig_header_len);
  return kAdSuccess;
}

int SigMgr::UnloadSigs() {
  for (std::vector<SigItem*>::iterator it = section_vector_.begin();
       it != section_vector_.end(); ++it) {
    free(*it);
  }

  // clear all vector
  malware_type_vector_.clear();
  malware_type_vector_.clear();
  platform_vector_.clear();
  file_format_vector_.clear();
  variant_vector_.clear();
  family_name_vector_.clear();
  family_id_vector_.clear();
  ad_info_vector_.clear();
  section_vector_.clear();

  // free the file buffer
  free(file_buffer_ptr_);
  file_buffer_ptr_ = nullptr;

  return 0;
}

int SigMgr::UpdateSigs(const char* dir) {
  int ret;

  UnloadSigs();
  ret = CheckAndLoadSigs(sig_file_path_, nullptr, false);
  if (ret != kAdSuccess) {
    UnloadSigs();
    CheckAndLoadSigs(sig_file_path_, nullptr, false);
  }

  return ret;
}

int SigMgr::SigVersion() { return sig_header_.version; }

int SigMgr::GetData(SigFormat format, SigItem** item) {
  for (std::vector<SigItem*>::iterator it = section_vector_.begin();
       it != section_vector_.end(); ++it) {
    if ((*it)->format == format) {
      *item = *it;
      return kAdSuccess;
    }
  }

  return kAdError;
}

int SigMgr::GetAdInfo(int sig_id, void** ad_info) {
  *ad_info = nullptr;
  for (std::vector<AdInfoNode>::iterator it = ad_info_vector_.begin();
       it != ad_info_vector_.end(); ++it) {
    if ((it)->sig_id == sig_id) {
      *ad_info = (it)->ad_info;
      return kAdSuccess;
    }
  }

  return kAdError;
}

int SigMgr::GetMalwareName(int sig_id, char* name_buf, int name_buf_size) {
  if (nullptr == name_buf || name_buf_size <= 0) return kAdError;

  SigItem* sig_item = nullptr;

  // Resolve sig_id -> name_id via the SIG section.
  if (kAdSuccess != GetData(kSigFormatSig, &sig_item) || nullptr == sig_item)
    return kAdError;
  int name_id = -1;
  {
    const char* base = static_cast<const char*>(sig_item->buf);
    const int bufsz = static_cast<int>(sig_item->buf_size);
    int index = 0;
    while (index + static_cast<int>(sizeof(SigName)) <= bufsz) {
      SigName sig_name;
      memcpy(&sig_name, base + index, sizeof(sig_name));
      if (sig_name.sig_id == static_cast<uint32_t>(sig_id)) {
        name_id = static_cast<int>(sig_name.name_id);
        break;
      }
      index += static_cast<int>(sizeof(SigName));
    }
  }

  if (name_id < 0) return kAdSuccess;

  // Resolve name_id -> MalwareName via the NAME section.
  if (kAdSuccess != GetData(kSigFormatName, &sig_item) || nullptr == sig_item)
    return kAdError;
  const char* base = static_cast<const char*>(sig_item->buf);
  const int bufsz = static_cast<int>(sig_item->buf_size);
  int index = 0;
  while (index + static_cast<int>(sizeof(MalwareName)) <= bufsz) {
    MalwareName malware_name;
    memcpy(&malware_name, base + index, sizeof(malware_name));
    if (malware_name.id == static_cast<uint32_t>(name_id)) {
      // Find the family index for this name.
      size_t fam = 0;
      while (fam < family_id_vector_.size() &&
             static_cast<uint32_t>(family_id_vector_[fam]) !=
                 malware_name.family)
        ++fam;
      // Validate every table index before use so a malformed DB cannot drive an
      // out-of-bounds read.
      if (fam >= family_name_vector_.size() ||
          malware_name.type >= malware_type_vector_.size() ||
          malware_name.variant >= variant_vector_.size() ||
          malware_name.platform >= platform_vector_.size() ||
          malware_name.file_format >= file_format_vector_.size()) {
        return kAdError;
      }
      memset(name_buf, '\0', name_buf_size);
      snprintf(name_buf, name_buf_size, "%s!%s.%s@%s.%s",
               malware_type_vector_[malware_name.type].c_str(),
               family_name_vector_[fam].c_str(),
               variant_vector_[malware_name.variant].c_str(),
               platform_vector_[malware_name.platform].c_str(),
               file_format_vector_[malware_name.file_format].c_str());
      return kAdSuccess;
    }
    index += static_cast<int>(sizeof(MalwareName));
  }

  return kAdError;
}

int SigMgr::DealWithSection(SigItem* sig_item) {
  int ret = kAdSuccess;
  switch (sig_item->format) {
    case kSigFormatType:
      ret = BuildData(sig_item, malware_type_vector_);
      break;
    case kSigFormatFamily:
      ret = BuildDataFamily(sig_item);
      break;
    case kSigFormatAdInfo:
      ret = BuildDataAdinfo(sig_item);
      break;
    case kSigFormatFileFormat:
      ret = BuildData(sig_item, file_format_vector_);
      break;
    case kSigFormatPlatform:
      ret = BuildData(sig_item, platform_vector_);
      break;
    case kSigFormatVariant:
      ret = BuildData(sig_item, variant_vector_);
      break;
    default:
      break;
  }

  return ret;
}

// Reads a NUL-terminated string from `base[index, bufsz)` without scanning past
// the section. Returns the string length (excluding NUL), or -1 if no NUL is
// present within the section (malformed DB).
static int BoundedCStr(const char* base, int index, int bufsz,
                       std::string* out) {
  const char* p = base + index;
  size_t maxlen = static_cast<size_t>(bufsz - index);
  size_t len = strnlen(p, maxlen);
  if (len == maxlen) return -1;  // no terminator inside the section
  if (out != nullptr) out->assign(p, len);
  return static_cast<int>(len);
}

int SigMgr::BuildDataAdinfo(SigItem* sig_item) {
  char* base = static_cast<char*>(sig_item->buf);
  const int bufsz = static_cast<int>(sig_item->buf_size);
  int index = 0;

  while (index < bufsz) {
    AdInfoNode ad_info_node;
    memset(&ad_info_node, '\0', sizeof(AdInfoNode));
    ad_info_node.ad_info = base + index;

    // sig id (u32)
    if (bufsz - index < static_cast<int>(sizeof(uint32_t))) return kAdError;
    uint32_t sig_id = 0;
    memcpy(&sig_id, base + index, sizeof(sig_id));
    ad_info_node.sig_id = sig_id;
    index += static_cast<int>(sizeof(uint32_t));

    // ad type count (u8) + type array
    if (bufsz - index < 1) return kAdError;
    int count = static_cast<uint8_t>(base[index]);
    index += 1;
    if (bufsz - index < count) return kAdError;
    index += count;

    // ad action count (u8) + action array
    if (bufsz - index < 1) return kAdError;
    count = static_cast<uint8_t>(base[index]);
    index += 1;
    if (bufsz - index < count) return kAdError;
    index += count;

    // risk level (u8)
    if (bufsz - index < 1) return kAdError;
    index += 1;

    // ad id, ad en name, ad zh name (each NUL-terminated)
    for (int s = 0; s < 3; ++s) {
      int len = BoundedCStr(base, index, bufsz, nullptr);
      if (len < 0) return kAdError;
      index += len + 1;
    }

    index = static_cast<int>(AlignSize4(static_cast<uint32_t>(index)));
    ad_info_vector_.push_back(ad_info_node);
  }

  return kAdSuccess;
}

int SigMgr::BuildDataFamily(SigItem* sig_item) {
  char* base = static_cast<char*>(sig_item->buf);
  const int bufsz = static_cast<int>(sig_item->buf_size);
  int index = 0;

  while (index < bufsz) {
    if (bufsz - index < static_cast<int>(sizeof(uint32_t))) return kAdError;
    uint32_t id = 0;
    memcpy(&id, base + index, sizeof(id));
    family_id_vector_.push_back(static_cast<int>(id));
    index += static_cast<int>(sizeof(uint32_t));

    std::string str;
    int len = BoundedCStr(base, index, bufsz, &str);
    if (len < 0) return kAdError;
    family_name_vector_.push_back(str);
    index += len + 1;  // include the '\0'
    index = static_cast<int>(AlignSize4(static_cast<uint32_t>(index)));
  }

  return kAdSuccess;
}

int SigMgr::BuildData(SigItem* sig_item, std::vector<std::string>& data) {
  const char* base = static_cast<const char*>(sig_item->buf);
  const int bufsz = static_cast<int>(sig_item->buf_size);
  int index = 0;

  while (index < bufsz) {
    std::string str;
    int len = BoundedCStr(base, index, bufsz, &str);
    if (len < 0) return kAdError;
    data.push_back(str);
    AAV_LOGD("  %s", str.c_str());
    index += len + 1;  // include the '\0'
  }

  return kAdSuccess;
}

}  // namespace aav
