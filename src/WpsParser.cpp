#include "Parsers.h"
#include <cstring>
namespace radar {
static bool space(uint8_t c) { return c == ' ' || (c >= 9 && c <= 13); }
static void text(Text& field, const uint8_t* data, size_t length) {
    while (length && data[length - 1] == 0) --length;
    while (length && space(data[length - 1])) --length;
    while (length && space(*data)) { ++data; --length; }
    if (length) field.assign(data, length);
}
bool parseWpsAttributes(const uint8_t* data, size_t length, WpsIdentity& output) {
    WpsIdentity parsed{};
    constexpr uint8_t uuid[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,0xbb};
    if (!data && length) return false;
    size_t offset = 0;
    while (offset < length) {
        if (length - offset < 4) return false;
        const uint16_t type = (uint16_t(data[offset]) << 8) | data[offset + 1];
        const size_t size = (uint16_t(data[offset + 2]) << 8) | data[offset + 3];
        offset += 4;
        if (size > length - offset) return false;
        const auto* value = data + offset;
        switch (type) {
        case 0x1011: text(parsed.deviceName, value, size); break;
        case 0x1021: text(parsed.manufacturer, value, size); break;
        case 0x1023: text(parsed.modelName, value, size); break;
        case 0x1024: text(parsed.modelNumber, value, size); break;
        case 0x1042: text(parsed.serialNumber, value, size); break;
        case 0x1047: case 0x1048:
            if (size != 16) return false;
            (type == 0x1047 ? parsed.uuidE : parsed.uuidR).assign(value, size);
            if (std::memcmp(value, uuid, 16) == 0) parsed.evidence |= FixedUuid;
            break;
        default: break;
        }
        ++parsed.attributes;
        offset += size;
    }
    detectIdentityDefaults(parsed);
    output = parsed;
    return true;
}
template <size_t N> static void merge(Bytes<N>& dst, const Bytes<N>& src) {
    if (src.length && (!dst.length || (!src.truncated && dst.truncated) || src.length > dst.length)) dst = src;
}
void mergeIdentity(WpsIdentity& dst, const WpsIdentity& src) {
    merge(dst.deviceName, src.deviceName); merge(dst.manufacturer, src.manufacturer);
    merge(dst.modelName, src.modelName); merge(dst.modelNumber, src.modelNumber);
    merge(dst.serialNumber, src.serialNumber); merge(dst.uuidE, src.uuidE); merge(dst.uuidR, src.uuidR);
    dst.defaults |= src.defaults; dst.evidence |= src.evidence;
    if (src.attributes > dst.attributes) dst.attributes = src.attributes;
    detectIdentityDefaults(dst);
}
}
