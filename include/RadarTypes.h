#pragma once
#include <cstddef>
#include <cstdint>
#ifndef RADAR_COUNTRY
#define RADAR_COUNTRY "PL"
#endif
#ifndef RADAR_WPS_PROBE
#define RADAR_WPS_PROBE 0
#endif
#ifndef RADAR_DRIVER_COMPAT
#define RADAR_DRIVER_COMPAT 0
#endif
#ifndef RADAR_TRANSPORT_ONLY
#define RADAR_TRANSPORT_ONLY RADAR_DRIVER_COMPAT
#endif
#if RADAR_DRIVER_COMPAT && !RADAR_WPS_PROBE
#error Driver compatibility requires the manual WPS transport experiment
#endif
#if RADAR_TRANSPORT_ONLY && !RADAR_WPS_PROBE
#error Transport-only mode requires the manual WPS test
#endif

namespace radar {
constexpr const char* kFirmwareVersion = "1.0.17";
constexpr const char* kCountries[] = {"01", "PL", "US", "JP", "DE", "GB", "FR", "CA", "AU", "AT", "BE", "BG", "BR", "CH", "CN", "CY", "CZ", "DK", "EE", "ES", "FI", "GR", "HK", "HR", "HU", "IE", "IN", "IS", "IT", "KR", "LI", "LT", "LU", "LV", "MT", "MX", "NL", "NO", "NZ", "PT", "RO", "SE", "SI", "SK", "TW"};
constexpr size_t kCountryCount = sizeof(kCountries) / sizeof(kCountries[0]);
constexpr const char* kFirmwareVariant = RADAR_WPS_PROBE ?
    (RADAR_DRIVER_COMPAT ? (RADAR_TRANSPORT_ONLY ? "C" : "F") : "T") : "P";
constexpr size_t kMaxAps = 128;
constexpr size_t kMaxFrame = 2304;
constexpr size_t kQueueDepth = 12;
constexpr size_t kPcapDepth = 16;
constexpr uint32_t kDwellMs = 400;
enum Evidence : uint8_t { ProprietaryIe = 1, FixedUuid = 2, IdentityDefaults = 4 };
enum class Classification { BroadcomSignature, WpsOnly, NoSignature, InsufficientData };
enum class WpsState { Unknown, No, Yes };

template <size_t N> struct Bytes {
    uint8_t data[N]{};
    uint16_t length = 0;
    bool truncated = false;
    void assign(const uint8_t* value, size_t size) {
        length = static_cast<uint16_t>(size < N ? size : N);
        truncated = size > N;
        for (size_t i = 0; i < length; ++i) data[i] = value[i];
    }
};
using Text = Bytes<64>;
struct WpsIdentity {
    Text deviceName, manufacturer, modelName, modelNumber, serialNumber;
    Bytes<16> uuidE, uuidR;
    uint8_t defaults = 0;
    uint8_t evidence = 0;
    uint16_t attributes = 0;
};
struct VendorIe { uint8_t prefix[4]{}; uint8_t length = 0; };
struct Observation {
    uint8_t bssid[6]{};
    Bytes<32> ssid;
    int8_t rssi = -127;
    uint8_t channel = 0, captureChannel = 0, subtype = 0;
    uint16_t capabilities = 0;
    uint64_t seenUs = 0;
    bool ssidPresent = false, malformed = false, wpsAdvertised = false;
    uint8_t evidence = 0;
    WpsIdentity wps;
    uint8_t ieIds[32]{};
    VendorIe vendors[8]{};
    uint8_t vendorCount = 0;
    bool vendorOverflow = false;
};
struct AccessPoint {
    Observation info;
    uint32_t discoveryOrder = 0;
    uint64_t firstSeenUs = 0, lastSeenUs = 0;
    uint32_t advertisements = 0, completeAdvertisements = 0, malformedAdvertisements = 0;
    uint32_t beacons = 0, probeResponses = 0;
    int8_t maxRssi = -127;
    uint16_t captureChannels = 0;
};
struct Frame {
    uint64_t timestampUs = 0;
    uint16_t length = 0;
    int8_t rssi = 0; // Populated by RX; empty buffers stay zero-initialized in BSS.
    uint8_t channel = 0;
    uint8_t bytes[kMaxFrame]{};
};
struct ScanStats {
    char country[3] = RADAR_COUNTRY;
    uint64_t startedUs = 0, nowUs = 0;
    uint32_t received = 0, queueDrops = 0, oversizeDrops = 0, rejected = 0, malformed = 0;
    uint32_t storeDrops = 0, discardedOnPause = 0;
    uint32_t storeReplacements = 0;
    uint16_t listenedChannels = 0;
    uint8_t channel = 1, channelCount = 13;
    bool running = false, hopping = true;
};
const char* classificationName(Classification value);
const char* classificationLabel(Classification value);
const char* evidenceName(uint8_t bit);
const char* evidenceSource(uint8_t bit);
Classification classify(const AccessPoint& ap);
WpsState wpsState(const AccessPoint& ap);
const char* wpsStateName(WpsState state);
const char* wpsTargetError(const Observation& target);
void renderBytes(const uint8_t* bytes, size_t length, char* output, size_t capacity);
void renderMac(const uint8_t* bytes, char* output, size_t capacity);
bool hiddenSsid(const Bytes<32>& ssid);
}
