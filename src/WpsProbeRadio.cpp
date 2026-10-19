#include "WpsProbeRadio.h"
#if RADAR_WPS_PROBE
#include <esp_timer.h>
namespace radar {
bool WpsProbeRadio::tick(WpsProbe& probe, WifiScanner& scanner, Exporter& exporter, Frame& frame, const char* hardware) {
    if (probe.requested()) {
        previous_ = scanner.stats(); prepared_ = true;
        uint8_t station[6]{};
        const int macError = esp_wifi_get_mac(WIFI_IF_STA, station);
        probe.begin(station, esp_timer_get_time());
        if (macError) probe.setupFailure(macError, esp_timer_get_time());
        else if (!scanner.setRunning(false) || !scanner.selectChannel(probe.target().channel) ||
                 !scanner.probeCapture(true, probe.target().bssid, station) || !scanner.setRunning(true))
            probe.setupFailure(ESP_FAIL, esp_timer_get_time());
    }
    probe.tick(esp_timer_get_time());
    if (probe.pending(frame)) {
        // Public driver API only. Unsupported frame types stop the probe, without a driver bypass.
        const int error = esp_wifi_80211_tx(WIFI_IF_STA, frame.bytes, frame.length, true);
        probe.transmitted(error, esp_timer_get_time());
        // A failure may have queued cleanup for this generated session.
        if (probe.pending(frame)) {
            const int cleanupError = esp_wifi_80211_tx(WIFI_IF_STA, frame.bytes, frame.length, true);
            probe.transmitted(cleanupError, esp_timer_get_time());
        }
    }
    if (!probe.done() || probe.result().reported || !prepared_) return false;
    const bool paused = scanner.setRunning(false);
    bool restored = paused && scanner.probeCapture(false, nullptr, nullptr);
    if (paused) exporter.saveProbe(probe, hardware);
    restored = scanner.selectChannel(previous_.hopping ? 0 : previous_.channel) && restored;
    if (previous_.running && restored) restored = scanner.setRunning(true);
    probe.completeReport(restored); prepared_ = false; return true;
}
}
#endif
