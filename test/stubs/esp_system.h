#pragma once
#include <cstddef>
#include <cstdint>
inline void esp_fill_random(void* target, size_t length) {
    static uint32_t state = 0x52414452;
    auto* bytes = static_cast<uint8_t*>(target);
    for (size_t i = 0; i < length; ++i) { state = state * 1664525u + 1013904223u; bytes[i] = uint8_t(state >> 24); }
}
