#pragma once
#include "GpsTracker.h"
#include <HardwareSerial.h>
namespace radar {
class GroveGps : public GpsInput {
public:
    bool start(uint8_t pin, uint32_t baud) override {
        serial_.end(); serial_.setRxBufferSize(256);
        serial_.begin(baud, SERIAL_8N1, pin, -1);
        return bool(serial_);
    }
    void stop() override { serial_.end(); }
    int available() override { return serial_.available(); }
    int read() override { return serial_.read(); }
    void discard() override { serial_.flush(false); }
private:
    HardwareSerial serial_{1};
};
}
