#include "WpsProbeRadio.h"
#if RADAR_WPS_PROBE
#include <esp_timer.h>
#include <esp_system.h>
#include <cstring>
#include "DriverCompat.h"
namespace radar {
namespace {
int configureMac(const uint8_t* address, const char* country, bool& touched, bool& changed) {
    int error = esp_wifi_stop();
    if (error && error != ESP_ERR_WIFI_NOT_STARTED) return error;
    touched = true;
    error = esp_wifi_set_mac(WIFI_IF_STA, address);
    changed = error == ESP_OK;
    const int started = esp_wifi_start();
    if (error) return error;
    if (started) return started;
    if ((error = esp_wifi_set_ps(WIFI_PS_NONE))) return error;
    if ((error = esp_wifi_set_country_code(country, false))) return error;
    uint8_t actual[6]{};
    error = esp_wifi_get_mac(WIFI_IF_STA, actual);
    return error ? error : std::memcmp(actual, address, 6) ? ESP_FAIL : ESP_OK;
}
void send(WpsProbe& probe, const Frame& frame) {
#if RADAR_DRIVER_COMPAT
    const auto tx = transmitCompatible(frame, probe);
    probe.transmitted(tx.error, esp_timer_get_time(), tx.applied, tx.stockError, tx.observed);
#else
    const int error = esp_wifi_80211_tx(WIFI_IF_STA, frame.bytes, frame.length, true);
    probe.transmitted(error, esp_timer_get_time());
#endif
}
}
bool WpsProbeRadio::tick(WpsProbe& probe, WifiScanner& scanner, Exporter& exporter, Frame& frame, const char* hardware) {
    if (probe.requested()) {
        previous_ = scanner.stats(); prepared_ = true;
        macTouched_ = false;
        uint8_t station[6]{};
        int macError = esp_wifi_get_mac(WIFI_IF_STA, station);
        bool randomized = false;
        if (!macError && probe.randomStation()) {
            std::memcpy(originalMac_, station, sizeof(originalMac_));
            uint8_t generated[6]; bool distinct = false;
            for (unsigned attempt = 0; attempt < 4 && !distinct; ++attempt) {
                esp_fill_random(generated, sizeof(generated)); generated[0] = (generated[0] | 2) & 0xfe;
                distinct = std::memcmp(generated, originalMac_, 6) && std::memcmp(generated, probe.target().bssid, 6);
            }
            if (!distinct || !scanner.setRunning(false)) macError = ESP_FAIL;
            else {
                macError = configureMac(generated, previous_.country, macTouched_, randomized);
                if (randomized) std::memcpy(station, generated, sizeof(station));
            }
        }
        probe.begin(station, esp_timer_get_time());
        probe.stationChanged(randomized);
        if (macError) probe.setupFailure(macError, esp_timer_get_time());
        else if (!scanner.setRunning(false) || !scanner.selectChannel(probe.target().channel) ||
                 !scanner.probeCapture(true, probe.target().bssid, station) || !scanner.setRunning(true))
            probe.setupFailure(ESP_FAIL, esp_timer_get_time());
    }
    probe.tick(esp_timer_get_time());
    if (probe.pending(frame)) {
        send(probe, frame);
        // A failure may have queued cleanup for this generated session.
        if (probe.pending(frame)) {
            send(probe, frame);
        }
    }
    if (!prepared_ || probe.result().reported) return false;
    if (probe.done()) {
        const auto stats = scanner.stats();
        probe.captureDrops(stats.queueDrops - previous_.queueDrops, stats.oversizeDrops - previous_.oversizeDrops);
        const bool paused = scanner.setRunning(false);
        int macError = ESP_OK;
        if (macTouched_) {
            bool touched = false, changed = false;
            macError = paused ? configureMac(originalMac_, previous_.country, touched, changed) : ESP_FAIL;
        }
        probe.stationRestoration(macError);
        const bool filterRestored = paused && scanner.probeCapture(false, nullptr, nullptr);
        bool restored = filterRestored && !macError;
        restored = scanner.selectChannel(previous_.hopping ? 0 : previous_.channel) && restored;
        if (previous_.running && restored) restored = scanner.setRunning(true);
        probe.startRestoration(restored, previous_.running, esp_timer_get_time());
    }
    if (!probe.restoring()) return false;
    const auto& result = probe.result();
    if (result.restored && result.scanWasRunning && !result.scanRxFrames &&
        uint64_t(esp_timer_get_time()) - result.scanRestoreUs < 1500000ULL) return false;
    probe.completeReport(result.restored);
    // All report buffers are owned by the application. Capture stays in the restored state during this bounded SD write.
    exporter.saveProbe(probe, hardware);
    prepared_ = false; return true;
}
}
#endif
