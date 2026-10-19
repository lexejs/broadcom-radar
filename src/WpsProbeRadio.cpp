#include "WpsProbeRadio.h"
#if RADAR_WPS_PROBE
#include <esp_timer.h>
#include "DriverCompat.h"
namespace radar {
namespace {
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
        bool restored = paused && scanner.probeCapture(false, nullptr, nullptr);
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
