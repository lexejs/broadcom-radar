#include <Arduino.h>
#include <M5Cardputer.h>
#if RADAR_ADV
#include <utility/Keyboard/KeyboardReader/TCA8418.h>
#else
#include <utility/Keyboard/KeyboardReader/IOMatrix.h>
#endif
#include "DisplayUi.h"
#include "WpsProbeRadio.h"

namespace {
radar::WifiScanner scanner;
radar::AccessPointStore store;
radar::PcapRing pcap;
radar::Exporter exporter;
radar::DisplayUi ui;
radar::Frame frame;
#if RADAR_WPS_PROBE
radar::WpsProbe probe;
radar::WpsProbeRadio probeRadio;
#endif
uint32_t rejected = 0, malformed = 0;
bool scannerReady = false;
#if RADAR_ADV
constexpr const char* hardware = "M5Stack Cardputer ADV";
#else
constexpr const char* hardware = "M5Stack Cardputer";
#endif
}
void setup() {
    Serial.begin(115200);
    auto config = M5.config();
    config.external_spk = false; config.internal_spk = false;
    config.internal_mic = false; config.internal_imu = false; config.internal_rtc = false;
#if RADAR_ADV
    config.fallback_board = m5::board_t::board_M5CardputerADV;
#else
    config.fallback_board = m5::board_t::board_M5Cardputer;
#endif
    M5Cardputer.begin(config, false);
#if RADAR_ADV
    M5Cardputer.Keyboard.begin(std::make_unique<TCA8418KeyboardReader>());
#else
    M5Cardputer.Keyboard.begin(std::make_unique<IOMatrixKeyboardReader>());
#endif
    const bool displayReady = ui.begin();
#if RADAR_WPS_PROBE
    ui.attachProbe(probe);
#endif
    exporter.mount(); scannerReady = displayReady && scanner.begin();
    Serial.printf("Broadcom Radar %s; %s; %s; heap=%u\n", radar::kFirmwareVersion, hardware,
                  RADAR_WPS_PROBE ? "experimental manual WPS probe" : "passive-only", ESP.getFreeHeap());
    if (!scannerReady) {
        M5Cardputer.Display.fillScreen(TFT_BLACK);
        M5Cardputer.Display.setCursor(0, 0);
        M5Cardputer.Display.printf("BROADCOM RADAR\n%s\nRestart to retry", displayReady ? scanner.error() : "Display buffer unavailable");
    }
}
void loop() {
    M5Cardputer.update();
    M5Cardputer.Keyboard.updateKeyList();
    M5Cardputer.Keyboard.updateKeysState();
    if (!scannerReady) { delay(20); return; }
#if RADAR_WPS_PROBE
    if (probeRadio.tick(probe, scanner, exporter, frame, hardware)) ui.notify(exporter.message());
#endif
    scanner.tick();
    if (!exporter.busy()) for (unsigned i = 0; i < 6 && scanner.pop(frame); ++i) {
#if RADAR_WPS_PROBE
        if (probe.busy()) { probe.receive(frame); continue; }
#endif
        radar::Observation observation;
        pcap.add(frame);
        if (radar::parseAdvertisement(frame.bytes, frame.length, frame.rssi, frame.channel, frame.timestampUs, observation)) {
            if (observation.malformed) ++malformed;
            const auto* ap = store.observe(observation);
            auto stats = scanner.stats();
            if (exporter.needsDetection(observation, ap, stats.nowUs)) {
                const bool running = stats.running;
                if (running && !scanner.setRunning(false)) continue;
                stats = scanner.stats();
                stats.rejected = rejected; stats.malformed = malformed; stats.storeDrops = store.dropped();
                exporter.saveDetection(observation, ap, frame, stats, hardware);
                if (running) scanner.setRunning(true);
                ui.notify(exporter.message());
            }
        } else ++rejected;
    }
#if RADAR_WPS_PROBE
    if (probeRadio.tick(probe, scanner, exporter, frame, hardware)) ui.notify(exporter.message());
#endif
    ui.tick(store, scanner, exporter, pcap, rejected, malformed, hardware);
    static uint32_t lastHealth = 0;
    if (millis() - lastHealth >= 5000) {
        const auto stats = scanner.stats();
        Serial.printf("uptime_ms=%u heap=%u min_heap=%u aps=%u rx=%u queue_drops=%u store_drops=%u\n",
                      unsigned(millis()), ESP.getFreeHeap(), ESP.getMinFreeHeap(), unsigned(store.size()), stats.received, stats.queueDrops, store.dropped());
        lastHealth = millis();
    }
    delay(2);
}
