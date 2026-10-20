#pragma once
#include "RadarTypes.h"
namespace radar {
constexpr uint32_t kGpsBauds[] = {4800, 9600, 38400, 115200};
void formatCoordinate(int32_t e7, char* output, size_t capacity);
void formatGpsUtc(const GeoFix& fix, char* output, size_t capacity);
class GpsInput {
public:
    virtual ~GpsInput() = default;
    virtual bool start(uint8_t pin, uint32_t baud) = 0;
    virtual void stop() = 0;
    virtual int available() = 0;
    virtual int read() = 0;
    virtual void discard() = 0;
};
class GpsTracker {
public:
    explicit GpsTracker(GpsInput& input) : input_(input) {}
    bool configure(bool enabled, uint8_t pin, uint32_t baud);
    void tick(uint64_t nowUs);
    GeoFix at(uint64_t observationUs) const;
    bool enabled() const { return enabled_; }
    bool error() const { return error_; }
    uint8_t pin() const { return pin_; }
    uint32_t baud() const { return baud_; }
    uint32_t fixes() const { return fixes_; }
    uint32_t rejected() const { return rejected_; }
private:
    void clearInput();
    void feed(int byte, uint64_t nowUs);
    void sentence(uint64_t nowUs);
    GpsInput& input_;
    GeoFix current_, previous_;
    char line_[128]{};
    size_t used_ = 0;
    uint64_t lastTickUs_ = 0;
    uint32_t baud_ = 9600, activeBaud_ = 0, fixes_ = 0, rejected_ = 0;
    uint8_t pin_ = 2, activePin_ = 0;
    bool enabled_ = false, active_ = false, error_ = false;
};
}
