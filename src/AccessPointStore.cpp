#include "AccessPointStore.h"
#include <cstring>
namespace radar {
void AccessPointStore::clear() { size_ = 0; dropped_ = 0; }
const AccessPoint* AccessPointStore::observe(const Observation& obs) {
    size_t index = 0;
    while (index < size_ && std::memcmp(aps_[index].info.bssid, obs.bssid, 6)) ++index;
    if (index == size_) {
        if (size_ == kMaxAps) { ++dropped_; return nullptr; }
        aps_[size_] = AccessPoint{};
        aps_[size_].info = obs;
        if (obs.malformed) aps_[size_].info.wpsAdvertised = false;
        aps_[size_].firstSeenUs = obs.seenUs;
        ++size_;
    }
    auto& ap = aps_[index];
    ++ap.advertisements;
    if (obs.subtype == 8) ++ap.beacons; else ++ap.probeResponses;
    ap.lastSeenUs = obs.seenUs;
    ap.info.rssi = obs.rssi;
    if (obs.rssi > ap.maxRssi) ap.maxRssi = obs.rssi;
    if (obs.captureChannel >= 1 && obs.captureChannel <= 14) ap.captureChannels |= 1 << (obs.captureChannel - 1);
    if (obs.malformed) { ++ap.malformedAdvertisements; return &ap; }
    const bool firstComplete = ap.completeAdvertisements == 0;
    ++ap.completeAdvertisements;
    ap.info.malformed = false;
    bool visible = false;
    for (size_t i = 0; i < obs.ssid.length; ++i) visible |= obs.ssid.data[i] != 0;
    if (visible || firstComplete || !ap.info.ssidPresent) ap.info.ssid = obs.ssid;
    ap.info.ssidPresent |= obs.ssidPresent;
    ap.info.channel = obs.channel; ap.info.captureChannel = obs.captureChannel;
    ap.info.capabilities = obs.capabilities;
    ap.info.wpsAdvertised |= obs.wpsAdvertised;
    mergeIdentity(ap.info.wps, obs.wps);
    ap.info.evidence |= obs.evidence | ap.info.wps.evidence;
    for (size_t i = 0; i < 32; ++i) ap.info.ieIds[i] |= obs.ieIds[i];
    for (size_t i = 0; i < obs.vendorCount; ++i) {
        bool found = false;
        for (size_t j = 0; j < ap.info.vendorCount; ++j)
            found |= std::memcmp(&ap.info.vendors[j], &obs.vendors[i], sizeof(VendorIe)) == 0;
        if (!found) {
            if (ap.info.vendorCount < 8) ap.info.vendors[ap.info.vendorCount++] = obs.vendors[i];
            else ap.info.vendorOverflow = true;
        }
    }
    ap.info.vendorOverflow |= obs.vendorOverflow;
    return &ap;
}
size_t AccessPointStore::broadcomCount() const {
    size_t count = 0;
    for (size_t i = 0; i < size_; ++i) count += classify(aps_[i]) == Classification::BroadcomSignature;
    return count;
}
void PcapRing::add(const Frame& frame) {
    if (!enabled_ || frame.length < 36 || frame.length > kMaxFrame || !isAdvertisement(frame.bytes, frame.length)) return;
    frames_[next_] = frame;
    next_ = (next_ + 1) % kPcapDepth;
    if (count_ < kPcapDepth) ++count_; else ++overwritten_;
}
}
