#include "FieldIndicators.h"
#include <cstring>
namespace radar {
void FieldIndicators::enableLed(bool enabled) {
    led_ = enabled; pending_ = false; seenCount_ = replace_ = 0;
    if (!enabled && lit_) { hardware_.rgb(0, 0, 0); lit_ = false; }
}
void FieldIndicators::enableSound(bool enabled) {
    sound_ = enabled; soundError_ = false;
    if (tracking_) hardware_.silence();
    tracking_ = false;
}
void FieldIndicators::observe(const Observation& observation, uint64_t epoch) {
    if (!led_ || observation.malformed) return;
    if (epoch_ != epoch) { epoch_ = epoch; seenCount_ = replace_ = 0; pending_ = false; }
    if (!observation.evidence) return;
    size_t index = 0;
    while (index < seenCount_ && std::memcmp(seen_[index].bssid, observation.bssid, 6)) ++index;
    if (index == seenCount_) {
        if (seenCount_ < 32) ++seenCount_;
        else { index = replace_; replace_ = (replace_ + 1) % 32; }
        seen_[index] = Seen{}; std::memcpy(seen_[index].bssid, observation.bssid, 6);
    }
    if (observation.evidence & ~seen_[index].evidence) pending_ = true;
    seen_[index].evidence |= observation.evidence;
}
void FieldIndicators::tick(const ScanStats& stats, const AccessPoint* selected, bool power, uint32_t now) {
    if (lit_ && (!led_ || !power || now - pulseAt_ >= pulseDuration_)) {
        hardware_.rgb(0, 0, 0); lit_ = false;
    }
    const bool activity = received_ != stats.received;
    received_ = stats.received;
    if (!led_ || !power || !stats.running) pending_ = false;
    else if (!pulsed_ || now - lastPulse_ >= (pending_ ? 200u : 2000u)) {
        if (pending_ || activity) {
            hardware_.rgb(pending_ ? 28 : 0, pending_ ? 8 : 12, 0);
            pulseAt_ = lastPulse_ = now; pulseDuration_ = pending_ ? 80 : 20;
            lit_ = pulsed_ = true; pending_ = false;
        }
    }
    const bool fresh = selected && stats.nowUs >= selected->lastSeenUs &&
                       stats.nowUs - selected->lastSeenUs <= 15000000;
    if (!sound_ || !stats.running || !fresh) {
        if (tracking_) { hardware_.silence(); tracking_ = false; }
        return;
    }
    if (!hardware_.service(now)) {
        hardware_.silence(); sound_ = tracking_ = false; soundError_ = true;
        return;
    }
    int signal = selected->info.rssi;
    if (signal < -95) signal = -95;
    if (signal > -35) signal = -35;
    const uint32_t period = 2000 - (signal + 95) * 30;
    const bool changed = !tracking_ || std::memcmp(target_, selected->info.bssid, 6);
    if (changed || now - lastTone_ >= period) {
        if (!hardware_.tone()) {
            hardware_.silence(); sound_ = tracking_ = false; soundError_ = true;
        } else {
            std::memcpy(target_, selected->info.bssid, 6); lastTone_ = now; tracking_ = true;
        }
    }
}
}
