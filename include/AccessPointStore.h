#pragma once
#include "Parsers.h"
namespace radar {
bool matchingAdvertisementContext(const Frame& trigger, const Frame& context);
class AdvertisementCache {
public:
    void clear();
    void remember(const Frame& frame, const Observation& observation, uint64_t epoch);
    const Frame* companion(const Frame& trigger) const;
private:
    struct Entry { uint8_t bssid[6]{}; uint64_t lastSeen = 0; Frame beacon, response; };
    Entry entries_[2]{};
    uint64_t epoch_ = 0;
};
class AccessPointStore {
public:
    const AccessPoint* observe(const Observation& observation);
    void clear();
    size_t size() const { return size_; }
    const AccessPoint& at(size_t i) const { return aps_[i]; }
    size_t broadcomCount() const;
    uint32_t dropped() const { return dropped_; }
    uint32_t replacements() const { return replacements_; }
    void protect(const uint8_t* selected, const uint8_t* target = nullptr);
private:
    AccessPoint aps_[kMaxAps]{};
    size_t size_ = 0;
    uint32_t dropped_ = 0;
    uint32_t replacements_ = 0, nextDiscovery_ = 0;
    uint8_t protected_[2][6]{};
};
class PcapRing {
public:
    void enable(bool enabled) { enabled_ = enabled; clear(); }
    bool enabled() const { return enabled_; }
    void clear() { count_ = next_ = 0; overwritten_ = 0; }
    void add(const Frame& frame);
    size_t size() const { return count_; }
    uint32_t overwritten() const { return overwritten_; }
    const Frame& at(size_t i) const { return frames_[(next_ + kPcapDepth - count_ + i) % kPcapDepth]; }
private:
    Frame frames_[kPcapDepth]{};
    size_t count_ = 0, next_ = 0;
    uint32_t overwritten_ = 0;
    bool enabled_ = false;
};
}
