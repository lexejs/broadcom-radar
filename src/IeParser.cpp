#include "Parsers.h"
#include <cstring>
namespace radar {
bool isAdvertisement(const uint8_t* data, size_t length) {
    return data && length >= 2 && (data[0] == 0x80 || data[0] == 0x50);
}
bool parseAdvertisement(const uint8_t* data, size_t length, int8_t rssi,
                        uint8_t channel, uint64_t timestampUs, Observation& out) {
    out = Observation{};
    if (!isAdvertisement(data, length) || length < 36 || length > kMaxFrame) return false;
    // No DS, protected, ordered or fragmented management frames are interpreted.
    if ((data[1] & 0xc7) || (data[22] & 15)) return false;
    bool nonzero = false;
    for (size_t i = 0; i < 6; ++i) nonzero |= data[16 + i] != 0;
    if (!nonzero || (data[16] & 1)) return false;
    std::memcpy(out.bssid, data + 16, 6);
    out.rssi = rssi; out.channel = out.captureChannel = channel;
    out.seenUs = timestampUs; out.subtype = data[0] >> 4;
    out.capabilities = uint16_t(data[34]) | (uint16_t(data[35]) << 8);
    uint8_t wps[1024];
    size_t wpsLength = 0;
    size_t offset = 36;
    while (offset < length) {
        if (length - offset < 2) { out.malformed = true; break; }
        const uint8_t id = data[offset++], size = data[offset++];
        if (size > length - offset) { out.malformed = true; break; }
        const uint8_t* value = data + offset;
        out.ieIds[id >> 3] |= 1 << (id & 7);
        if (id == 0 && !out.ssidPresent) {
            out.ssid.assign(value, size); out.ssidPresent = true;
            if (size > 32) out.malformed = true;
        } else if ((id == 3 || id == 61) && size) {
            if (value[0] >= 1 && value[0] <= 14) out.channel = value[0];
        } else if (id == 221) {
            if (out.vendorCount < 8) {
                auto& vendor = out.vendors[out.vendorCount++];
                vendor.length = size;
                std::memcpy(vendor.prefix, value, size < 4 ? size : 4);
            } else out.vendorOverflow = true;
            constexpr uint8_t proprietary[] = {0,0x10,0x18,2};
            constexpr uint8_t wpsPrefix[] = {0,0x50,0xf2,4};
            if (size == 9 && std::memcmp(value, proprietary, 4) == 0) out.evidence |= ProprietaryIe;
            if (size >= 4 && std::memcmp(value, wpsPrefix, 4) == 0) {
                out.wpsAdvertised = true;
                if (size - 4u > sizeof(wps) - wpsLength) out.malformed = true;
                else { std::memcpy(wps + wpsLength, value + 4, size - 4); wpsLength += size - 4; }
            }
        }
        offset += size;
    }
    if (!out.ssidPresent) out.malformed = true;
    if (out.wpsAdvertised && (!wpsLength || !parseWpsAttributes(wps, wpsLength, out.wps))) out.malformed = true;
    if (out.malformed) { out.evidence = 0; out.wps = WpsIdentity{}; }
    else out.evidence |= out.wps.evidence;
    return true;
}
}
