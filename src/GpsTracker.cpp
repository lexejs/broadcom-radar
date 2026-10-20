#include "GpsTracker.h"
#include <cstdio>
#include <cstring>
namespace radar {
namespace {
int digit(char c) { return c >= '0' && c <= '9' ? c - '0' : -1; }
int hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}
int pair(const char* text) {
    const int a = digit(text[0]), b = digit(text[1]);
    return a < 0 || b < 0 ? -1 : a * 10 + b;
}
bool coordinate(const char* text, const char* hemisphere, bool latitude, int32_t& result) {
    const size_t width = latitude ? 4 : 5, length = std::strlen(text);
    if (length < width || length > width + 9 || std::strlen(hemisphere) != 1) return false;
    uint32_t degrees = 0, minutes = 0;
    for (size_t i = 0; i < width; ++i) {
        const int value = digit(text[i]); if (value < 0) return false;
        if (i < width - 2) degrees = degrees * 10 + value; else minutes = minutes * 10 + value;
    }
    uint32_t fraction = 0, scale = 1;
    if (length > width) {
        if (text[width] != '.' || length == width + 1) return false;
        for (size_t i = width + 1; i < length; ++i) {
            const int value = digit(text[i]); if (value < 0) return false;
            fraction = fraction * 10 + value; scale *= 10;
        }
    }
    const unsigned limit = latitude ? 90 : 180;
    if (minutes >= 60 || degrees > limit || (degrees == limit && (minutes || fraction))) return false;
    const char positive = latitude ? 'N' : 'E', negative = latitude ? 'S' : 'W';
    if (hemisphere[0] != positive && hemisphere[0] != negative) return false;
    const int64_t value = int64_t(degrees) * 10000000 + ((int64_t(minutes) * scale + fraction) * 10000000) / (60 * int64_t(scale));
    result = hemisphere[0] == negative ? -value : value; return true;
}
bool utc(const char* time, const char* date, GeoFix& fix) {
    const size_t length = std::strlen(time);
    if (length < 6 || length > 13 || std::strlen(date) != 6) return false;
    if (length > 6) {
        if (time[6] != '.' || length == 7) return false;
        for (size_t i = 7; i < length; ++i) if (digit(time[i]) < 0) return false;
    }
    const int hour = pair(time), minute = pair(time + 2), second = pair(time + 4);
    const int day = pair(date), month = pair(date + 2), year = pair(date + 4);
    if (hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59 ||
        year < 0 || month < 1 || month > 12 || day < 1) return false;
    const unsigned fullYear = year >= 80 ? 1900 + year : 2000 + year;
    static const unsigned days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    const bool leap = fullYear % 4 == 0 && (fullYear % 100 != 0 || fullYear % 400 == 0);
    if (unsigned(day) > days[month - 1] + (month == 2 && leap ? 1 : 0)) return false;
    fix.date = fullYear * 10000 + month * 100 + day;
    fix.seconds = hour * 3600 + minute * 60 + second; return true;
}
}
void formatCoordinate(int32_t e7, char* output, size_t capacity) {
    const uint32_t absolute = e7 < 0 ? -int64_t(e7) : e7;
    std::snprintf(output, capacity, "%s%u.%07u", e7 < 0 ? "-" : "", unsigned(absolute / 10000000), unsigned(absolute % 10000000));
}
void formatGpsUtc(const GeoFix& fix, char* output, size_t capacity) {
    std::snprintf(output, capacity, "%04u-%02u-%02uT%02u:%02u:%02uZ", unsigned(fix.date / 10000),
                  unsigned(fix.date / 100 % 100), unsigned(fix.date % 100), unsigned(fix.seconds / 3600),
                  unsigned(fix.seconds / 60 % 60), unsigned(fix.seconds % 60));
}
void GpsTracker::clearInput() { used_ = 0; current_ = previous_ = GeoFix{}; lastTickUs_ = 0; }
bool GpsTracker::configure(bool enabled, uint8_t pin, uint32_t baud) {
    bool supported = false; for (auto value : kGpsBauds) supported |= value == baud;
    if ((pin != 1 && pin != 2) || !supported) return false;
    if (enabled_ != enabled || pin_ != pin || baud_ != baud) clearInput();
    enabled_ = enabled; pin_ = pin; baud_ = baud; error_ = false; return true;
}
GeoFix GpsTracker::at(uint64_t observationUs) const {
    if (!enabled_) return {};
    if (current_.validAt(observationUs)) return current_;
    if (previous_.validAt(observationUs)) return previous_;
    return {};
}
void GpsTracker::tick(uint64_t nowUs) {
    if (!enabled_) {
        if (active_) { input_.stop(); active_ = false; clearInput(); }
        return;
    }
    if (!active_ || activePin_ != pin_ || activeBaud_ != baud_) {
        clearInput();
        if (!input_.start(pin_, baud_)) { input_.stop(); active_ = enabled_ = false; error_ = true; return; }
        active_ = true; activePin_ = pin_; activeBaud_ = baud_;
    }
    // A main-loop stall can leave old UART bytes. Do not stamp those as a fresh fix.
    if (lastTickUs_ && (nowUs < lastTickUs_ || nowUs - lastTickUs_ > 250000)) {
        input_.discard(); clearInput(); lastTickUs_ = nowUs; return;
    }
    lastTickUs_ = nowUs;
    for (unsigned budget = 0; budget < 64 && input_.available() > 0; ++budget) feed(input_.read(), nowUs);
}
void GpsTracker::feed(int byte, uint64_t nowUs) {
    if (byte == '$') { used_ = 1; line_[0] = '$'; return; }
    if (!used_) return;
    if (byte == '\r') return;
    if (byte == '\n') { line_[used_] = 0; sentence(nowUs); used_ = 0; return; }
    if (byte < 32 || byte > 126 || used_ + 1 >= sizeof(line_)) { used_ = 0; ++rejected_; return; }
    line_[used_++] = char(byte);
}
void GpsTracker::sentence(uint64_t nowUs) {
    char* star = std::strchr(line_, '*');
    if (!star || std::strlen(star) != 3 || hex(star[1]) < 0 || hex(star[2]) < 0) { ++rejected_; return; }
    uint8_t checksum = 0; for (char* p = line_ + 1; p < star; ++p) checksum ^= *p;
    if (checksum != (hex(star[1]) * 16 + hex(star[2]))) { ++rejected_; return; }
    *star = 0;
    char* fields[16]{}; size_t count = 1; fields[0] = line_ + 1;
    for (char* p = fields[0]; *p; ++p) if (*p == ',') {
        *p = 0; if (count == 16) { ++rejected_; return; } fields[count++] = p + 1;
    }
    if (std::strlen(fields[0]) != 5 || std::strcmp(fields[0] + 2, "RMC")) return;
    if (fields[0][0] < 'A' || fields[0][0] > 'Z' || fields[0][1] < 'A' || fields[0][1] > 'Z') return;
    GeoFix fix;
    if (count < 10 || std::strcmp(fields[2], "A") ||
        (count > 12 && fields[12][0] && (std::strlen(fields[12]) != 1 || !std::strchr("ADFRP", fields[12][0]))) ||
        !coordinate(fields[3], fields[4], true, fix.latitudeE7) ||
        !coordinate(fields[5], fields[6], false, fix.longitudeE7) || !utc(fields[1], fields[9], fix)) {
        current_ = previous_ = GeoFix{}; ++rejected_; return;
    }
    fix.receivedUs = nowUs; previous_ = current_; current_ = fix; ++fixes_;
}
}
