#pragma once
#include "RadarTypes.h"
namespace radar {
// Input is raw 802.11 without FCS. False means no attributable advertisement.
bool parseAdvertisement(const uint8_t* data, size_t length, int8_t rssi,
                        uint8_t channel, uint64_t timestampUs, Observation& result);
bool parseWpsAttributes(const uint8_t* data, size_t length, WpsIdentity& result);
void detectIdentityDefaults(WpsIdentity& identity);
void mergeIdentity(WpsIdentity& target, const WpsIdentity& source);
bool isAdvertisement(const uint8_t* data, size_t length);
}
