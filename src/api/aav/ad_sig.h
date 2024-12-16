#ifndef AAV_AD_SIG_H_
#define AAV_AD_SIG_H_

#include <stdint.h>

namespace aav {

enum AdType {
  kAdTypeUnknown = 0,
  kAdTypeBanner,
  kAdTypeFullScreen,
  kAdTypeInterstitialScreen,
  kAdTypeVideo,
  kAdTypeRichMedia,
  kAdTypeWall,
  kAdTypeNotify,
};

enum RiskLevel {
  kRiskLevelUnknown = 0,
  kRiskLevelNoAd,
  kRiskLevelSafeAd,
  kRiskLevelRiskAd,
  kRiskLevelMalwareAd,
};

#pragma pack(push, 1)

struct AdInfo {
  uint32_t sig_id;
  uint8_t ad_type_count;
  uint8_t ad_types[1];
  uint8_t ad_action_count;
  uint8_t ad_actions[1];
  uint8_t risk_level;
  uint8_t ad_id[1];
  uint8_t ad_en_name[1];
  uint8_t ad_zh_name[1];
};

#pragma pack(pop)

}  // namespace aav

#endif
