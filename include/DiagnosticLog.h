#pragma once
#include <cstddef>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
namespace radar {
// One main-loop writer owns the USB port. Drop a snapshot rather than wait for a host.
class DiagnosticLog {
public:
    bool format(const char* format, ...) {
        if (pending()) return false;
        va_list args; va_start(args, format);
        const int count = std::vsnprintf(bytes_, sizeof(bytes_), format, args); va_end(args);
        offset_ = length_ = 0;
        if (count < 0 || size_t(count) >= sizeof(bytes_)) return false;
        length_ = count; return true;
    }
    bool pending() const { return offset_ < length_; }
    template<class Port> void tick(Port& port) {
        if (!port) { offset_ = length_ = 0; return; }
        if (!pending()) return;
        const int available = port.availableForWrite();
        if (available <= 0) return;
        size_t count = length_ - offset_;
        if (count > 32) count = 32;
        if (count > size_t(available)) count = available;
        // Arduino 2.0.17 USBCDC::write ignores its timeout once the TX FIFO fills.
        // A single writer submits only bytes already covered by available capacity.
        const size_t written = port.write(reinterpret_cast<const uint8_t*>(bytes_) + offset_, count);
        if (written <= count) offset_ += written;
    }
private:
    char bytes_[256]{};
    size_t length_ = 0, offset_ = 0;
};
}
