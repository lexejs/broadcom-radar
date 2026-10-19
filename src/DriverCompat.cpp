#include "DriverCompat.h"
#if RADAR_DRIVER_COMPAT
#include <esp_wifi.h>
#include <cstring>

// ABI verified against the SHA-pinned ESP32-S3 IDF 4.4.7 object at build time.
extern "C" int radar_stock_raw_frame_check(int interface, const void* buffer, int length, bool sequence);
namespace {
const void* authorizedBuffer = nullptr;
int authorizedLength = 0;
bool extendManagement = false;
radar::CompatTxResult outcome;
bool managementRequest(const radar::Frame& frame, const radar::WpsProbe& probe) {
    const auto* p = frame.bytes; const size_t n = frame.length;
    if (!probe.result().transportOnly || !probe.busy() || n < 26 || n > radar::kProbeBytes || p[1] ||
        p[2] || p[3] || (p[22] & 15) || std::memcmp(p + 4, probe.target().bssid, 6) ||
        std::memcmp(p + 10, probe.station(), 6) || std::memcmp(p + 16, probe.target().bssid, 6)) return false;
    const auto stage = probe.result().stage;
    constexpr uint8_t auth[] = {0,0,1,0,0,0};
    if (stage == radar::ProbeStage::Authentication)
        return p[0] == 0xb0 && n == 30 && !std::memcmp(p + 24, auth, sizeof(auth));
    if (stage == radar::ProbeStage::Cleanup) return p[0] == 0xc0 && n == 26 && p[24] == 3 && p[25] == 0;
    if (stage != radar::ProbeStage::Association || p[0] || n < 44 || p[26] != 10 || p[27]) return false;
    constexpr uint8_t wps[] = {221,14,0,0x50,0xf2,4,0x10,0x4a,0,1,0x10,0x10,0x3a,0,1,1};
    if (std::memcmp(p + n - sizeof(wps), wps, sizeof(wps))) return false;
    bool ssid = false;
    for (size_t i = 28; i < n;) {
        if (n - i < 2 || size_t(p[i + 1]) + 2 > n - i) return false;
        if (p[i] == 0) {
            if (ssid || p[i + 1] != probe.target().ssid.length ||
                std::memcmp(p + i + 2, probe.target().ssid.data, p[i + 1])) return false;
            ssid = true;
        }
        i += size_t(p[i + 1]) + 2;
    }
    return ssid;
}
}
extern "C" __attribute__((used, noinline)) int ieee80211_raw_frame_sanity_check(int interface, const void* buffer, int length, bool sequence) {
    const int stock = radar_stock_raw_frame_check(interface, buffer, length, sequence);
    // The original check always runs. Only this synchronous, locally generated management request can be extended.
    if (authorizedBuffer && buffer == authorizedBuffer && length == authorizedLength && interface == WIFI_IF_STA && sequence) {
        outcome.stockError = stock; outcome.observed = true;
        if (extendManagement && stock == ESP_ERR_INVALID_ARG) { outcome.applied = true; return ESP_OK; }
    }
    return stock;
}
namespace radar {
CompatTxResult transmitCompatible(const Frame& frame, const WpsProbe& probe) {
    outcome = CompatTxResult{};
    if (!probe.result().transportOnly || !probe.matchesPending(frame)) { outcome.error = ESP_ERR_INVALID_ARG; return outcome; }
    const bool management = frame.length && (frame.bytes[0] & 0x0c) == 0;
    if (management && !managementRequest(frame, probe)) { outcome.error = ESP_ERR_INVALID_ARG; return outcome; }
    authorizedLength = frame.length;
    extendManagement = management; authorizedBuffer = frame.bytes;
    outcome.error = esp_wifi_80211_tx(WIFI_IF_STA, frame.bytes, frame.length, true);
    authorizedBuffer = nullptr; authorizedLength = 0; extendManagement = false;
    return outcome;
}
}
#endif
