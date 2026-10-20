#pragma once
#include "RadarTypes.h"
namespace radar {
class IndicatorHardware {
public:
    virtual ~IndicatorHardware() = default;
    virtual void rgb(uint8_t red, uint8_t green, uint8_t blue) = 0;
    virtual bool tone() = 0;
    virtual void silence() = 0;
};
class FieldIndicators {
public:
    explicit FieldIndicators(IndicatorHardware& hardware) : hardware_(hardware) {}
    bool ledEnabled() const { return led_; }
    bool soundEnabled() const { return sound_; }
    bool soundError() const { return soundError_; }
    void enableLed(bool enabled);
    void enableSound(bool enabled);
    void observe(const Observation& observation, uint64_t epoch);
    void tick(const ScanStats& stats, const AccessPoint* selected, bool rgbPowerAvailable, uint32_t nowMs);
private:
    struct Seen { uint8_t bssid[6]{}; uint8_t evidence = 0; };
    IndicatorHardware& hardware_;
    Seen seen_[32]{};
    size_t seenCount_ = 0, replace_ = 0;
    uint64_t epoch_ = 0;
    uint32_t received_ = 0, pulseAt_ = 0, pulseDuration_ = 0, lastPulse_ = 0, lastTone_ = 0;
    uint8_t target_[6]{};
    bool led_ = false, sound_ = false, soundError_ = false, pending_ = false;
    bool lit_ = false, pulsed_ = false, tracking_ = false;
};
}
