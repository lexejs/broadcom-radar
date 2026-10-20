#include "AccessPointStore.h"
#include <cstring>
namespace radar {
void recordAdvertisementSource(AccessPoint& ap, const Observation& observation) {
    if (observation.malformed) return;
    const uint8_t source = observation.subtype == 8 ? 1 : observation.subtype == 5 ? 2 : 0;
    ap.metadataSources |= source;
    if (observation.wpsAdvertised) ap.wpsSources |= source;
    if (source == 1) { ap.beaconEvidence |= observation.evidence; ap.beaconDefaults |= observation.wps.defaults; }
    if (source == 2) { ap.responseEvidence |= observation.evidence; ap.responseDefaults |= observation.wps.defaults; }
}
uint8_t evidenceFrameSources(const AccessPoint& ap, uint8_t evidence) {
    if (evidence == IdentityDefaults) return (ap.beaconDefaults ? 1 : 0) | (ap.responseDefaults ? 2 : 0);
    return ((ap.beaconEvidence & evidence) ? 1 : 0) | ((ap.responseEvidence & evidence) ? 2 : 0);
}
bool matchingAdvertisementContext(const Frame& trigger, const Frame& context) {
    return trigger.length >= 36 && trigger.length <= kMaxFrame && context.length >= 36 && context.length <= kMaxFrame &&
        (trigger.bytes[0] == 0x80 || trigger.bytes[0] == 0x50) && (context.bytes[0] == 0x80 || context.bytes[0] == 0x50) &&
        trigger.bytes[0] != context.bytes[0] && trigger.channel == context.channel &&
        !std::memcmp(trigger.bytes + 16, context.bytes + 16, 6) && context.timestampUs <= trigger.timestampUs &&
        trigger.timestampUs - context.timestampUs <= 30000000ULL;
}
void AdvertisementCache::clear() {
    for (auto& entry : entries_) {
        entry.beacon.length = entry.response.length = 0; entry.lastSeen = 0;
        std::memset(entry.bssid, 0, sizeof(entry.bssid));
    }
}
void AdvertisementCache::remember(const Frame& frame, const Observation& observation, uint64_t epoch) {
    if (epoch_ != epoch) { clear(); epoch_ = epoch; }
    if (observation.malformed || frame.length < 36 || frame.length > kMaxFrame ||
        (frame.bytes[0] != 0x80 && frame.bytes[0] != 0x50) || std::memcmp(frame.bytes + 16, observation.bssid, 6)) return;
    Entry* selected = nullptr;
    for (auto& entry : entries_) if (!std::memcmp(entry.bssid, observation.bssid, 6)) selected = &entry;
    if (!selected) {
        selected = &entries_[0];
        for (auto& entry : entries_) if (entry.lastSeen < selected->lastSeen) selected = &entry;
        selected->beacon.length = selected->response.length = 0;
        std::memcpy(selected->bssid, observation.bssid, 6);
    }
    (frame.bytes[0] == 0x80 ? selected->beacon : selected->response) = frame;
    selected->lastSeen = frame.timestampUs;
}
const Frame* AdvertisementCache::companion(const Frame& trigger) const {
    for (const auto& entry : entries_) {
        const Frame& candidate = trigger.bytes[0] == 0x80 ? entry.response : entry.beacon;
        if (matchingAdvertisementContext(trigger, candidate)) return &candidate;
    }
    return nullptr;
}
void AccessPointStore::clear() {
    size_ = 0; dropped_ = replacements_ = nextDiscovery_ = 0;
    std::memset(protected_, 0, sizeof(protected_));
}
void AccessPointStore::protect(const uint8_t* selected, const uint8_t* target) {
    const uint8_t* addresses[] = {selected, target};
    for (size_t i = 0; i < 2; ++i) {
        if (addresses[i]) std::memcpy(protected_[i], addresses[i], 6);
        else std::memset(protected_[i], 0, 6);
    }
}
const AccessPoint* AccessPointStore::observe(const Observation& obs) {
    size_t index = 0;
    while (index < size_ && std::memcmp(aps_[index].info.bssid, obs.bssid, 6)) ++index;
    if (index == size_) {
        if (size_ == kMaxAps) {
            size_t victim = kMaxAps;
            for (size_t i = 0; i < size_; ++i) {
                const auto state = classify(aps_[i]);
                if (state != Classification::NoSignature && state != Classification::InsufficientData) continue;
                if (!std::memcmp(aps_[i].info.bssid, protected_[0], 6) ||
                    !std::memcmp(aps_[i].info.bssid, protected_[1], 6)) continue;
                if (victim == kMaxAps || aps_[i].lastSeenUs < aps_[victim].lastSeenUs ||
                    (aps_[i].lastSeenUs == aps_[victim].lastSeenUs && aps_[i].info.rssi < aps_[victim].info.rssi)) victim = i;
            }
            if (victim == kMaxAps) { ++dropped_; return nullptr; }
            index = victim; ++replacements_;
        } else ++size_;
        aps_[index] = AccessPoint{};
        aps_[index].info = obs;
        aps_[index].discoveryOrder = nextDiscovery_++;
        if (obs.malformed) aps_[index].info.wpsAdvertised = false;
        aps_[index].firstSeenUs = obs.seenUs;
    }
    auto& ap = aps_[index];
    ++ap.advertisements;
    if (obs.subtype == 8) ++ap.beacons; else ++ap.probeResponses;
    ap.lastSeenUs = obs.seenUs;
    ap.info.rssi = obs.rssi;
    if (obs.rssi > ap.maxRssi) ap.maxRssi = obs.rssi;
    if (obs.captureChannel >= 1 && obs.captureChannel <= 14) ap.captureChannels |= 1 << (obs.captureChannel - 1);
    if (obs.malformed) { ++ap.malformedAdvertisements; return &ap; }
    recordAdvertisementSource(ap, obs);
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
