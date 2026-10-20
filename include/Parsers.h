#pragma once
#include "RadarTypes.h"
namespace radar {
// One reusable workspace per serialized caller/task; no shared global scratch.
class AdvertisementParser {
public:
    bool parse(const uint8_t* data, size_t length, int8_t rssi,
               uint8_t channel, uint64_t timestampUs, Observation& result);
private:
    uint8_t wps_[1024];
};
// Input is raw 802.11 without FCS. False means no attributable advertisement.
// Convenience wrapper owns its workspace on the calling stack.
bool parseAdvertisement(const uint8_t* data, size_t length, int8_t rssi,
                        uint8_t channel, uint64_t timestampUs, Observation& result);
bool parseWpsAttributes(const uint8_t* data, size_t length, WpsIdentity& result);
void detectIdentityDefaults(WpsIdentity& identity);
void mergeIdentity(WpsIdentity& target, const WpsIdentity& source);
bool isAdvertisement(const uint8_t* data, size_t length);
}
