#pragma once
#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>
namespace fixtures {
using Data = std::vector<uint8_t>;
inline void ie(Data& frame, uint8_t id, const Data& value) {
    frame.push_back(id); frame.push_back(static_cast<uint8_t>(value.size()));
    frame.insert(frame.end(), value.begin(), value.end());
}
inline Data beacon(const Data& ssid = {'T','e','s','t'}, uint8_t bssidSuffix = 1) {
    Data frame(36, 0); frame[0] = 0x80;
    for (int i = 4; i < 10; ++i) frame[i] = 0xff;
    frame[10] = frame[16] = 2; frame[15] = frame[21] = bssidSuffix;
    frame[32] = 100; frame[34] = 0x11;
    ie(frame, 0, ssid); ie(frame, 3, {6});
    return frame;
}
inline Data text(const std::string& value) { return Data(value.begin(), value.end()); }
inline void tlv(Data& data, uint16_t type, const Data& value) {
    data.push_back(type >> 8); data.push_back(type & 255);
    data.push_back(value.size() >> 8); data.push_back(value.size() & 255);
    data.insert(data.end(), value.begin(), value.end());
}
inline void wps(Data& frame, const Data& tlvs) {
    Data payload = {0,0x50,0xf2,4}; payload.insert(payload.end(), tlvs.begin(), tlvs.end()); ie(frame, 221, payload);
}
inline void proprietary(Data& frame, size_t length = 9) {
    Data payload = {0,0x10,0x18,2}; payload.resize(length); ie(frame, 221, payload);
}
inline Data ordinaryWps() { auto f = beacon(); Data t; tlv(t, 0x1021, text("Example Vendor")); wps(f, t); return f; }
inline Data fixedUuid(bool registrar = false) {
    auto f = beacon(); Data t; tlv(t, registrar ? 0x1048 : 0x1047, {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,0xbb}); wps(f, t); return f;
}
inline Data defaults() {
    auto f = beacon(); Data t; tlv(t, 0x1021, text(" bRoAdCoM ")); tlv(t, 0x1024, text("1234")); wps(f, t); return f;
}
}
