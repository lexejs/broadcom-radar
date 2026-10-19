#include "Parsers.h"
#include <cstdio>
#include <cstring>

namespace radar {
static bool equals(const Text& text, const char* expected) {
    const size_t n = std::strlen(expected);
    if (text.truncated || text.length != n) return false;
    for (size_t i = 0; i < n; ++i) {
        uint8_t c = text.data[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c != static_cast<uint8_t>(expected[i])) return false;
    }
    return true;
}
void detectIdentityDefaults(WpsIdentity& wps) {
    if (equals(wps.manufacturer, "broadcom")) wps.defaults |= 1;
    if (equals(wps.modelName, "broadcom") || equals(wps.modelName, "broadcomap")) wps.defaults |= 2;
    if (equals(wps.modelNumber, "1234") || equals(wps.modelNumber, "123456")) wps.defaults |= 4;
    if (equals(wps.deviceName, "broadcomap")) wps.defaults |= 8;
    unsigned count = 0;
    for (uint8_t bits = wps.defaults; bits; bits >>= 1) count += bits & 1;
    if (count >= 2) wps.evidence |= IdentityDefaults;
}
Classification classify(const AccessPoint& ap) {
    if (ap.info.evidence) return Classification::BroadcomSignature;
    if (!ap.completeAdvertisements) return Classification::InsufficientData;
    if (ap.info.wpsAdvertised) return Classification::WpsOnly;
    return Classification::NoSignature;
}
WpsState wpsState(const AccessPoint& ap) {
    if (ap.info.wpsAdvertised) return WpsState::Yes;
    return ap.completeAdvertisements ? WpsState::No : WpsState::Unknown;
}
const char* wpsStateName(WpsState state) {
    return state == WpsState::Yes ? "YES" : state == WpsState::No ? "NO" : "UNKNOWN";
}
const char* classificationName(Classification value) {
    switch (value) {
    case Classification::BroadcomSignature: return "BROADCOM_SIGNATURE";
    case Classification::WpsOnly: return "WPS_ONLY";
    case Classification::NoSignature: return "NO_SIGNATURE";
    default: return "INSUFFICIENT_DATA";
    }
}
const char* classificationLabel(Classification value) {
    switch (value) {
    case Classification::BroadcomSignature: return "BRCM DETECTED";
    case Classification::WpsOnly: return "WPS / UNKNOWN";
    case Classification::NoSignature: return "NO SIGNATURE";
    default: return "INCONCLUSIVE";
    }
}
const char* evidenceName(uint8_t bit) {
    switch (bit) {
    case ProprietaryIe: return "broadcom_proprietary_ie";
    case FixedUuid: return "broadcom_fixed_wps_uuid";
    case IdentityDefaults: return "broadcom_wps_identity_defaults";
    default: return "unknown";
    }
}
const char* evidenceSource(uint8_t bit) {
    switch (bit) {
    case ProprietaryIe: return "Vendor IE 221: 00101802, payload length exactly 9";
    case FixedUuid: return "WPS UUID-E/UUID-R: 000102030405060708090a0b0c0d0ebb";
    case IdentityDefaults: return "At least two distinct WPS default identity fields across complete advertisements";
    default: return "unknown";
    }
}
void renderBytes(const uint8_t* bytes, size_t length, char* out, size_t capacity) {
    if (!capacity) return;
    size_t used = 0;
    constexpr char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < length; ++i) {
        const uint8_t c = bytes[i];
        const bool printable = c >= 32 && c <= 126 && c != '\\';
        size_t need = printable ? 1 : 4;
        if (used + need >= capacity) break;
        if (printable) out[used++] = static_cast<char>(c);
        else { out[used++] = '\\'; out[used++] = 'x'; out[used++] = hex[c >> 4]; out[used++] = hex[c & 15]; }
    }
    out[used] = 0;
}
void renderMac(const uint8_t* b, char* out, size_t capacity) {
    std::snprintf(out, capacity, "%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5]);
}
bool hiddenSsid(const Bytes<32>& ssid) {
    for (size_t i = 0; i < ssid.length; ++i) if (ssid.data[i]) return false;
    return true;
}
}
