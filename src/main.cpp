#include <Arduino.h>
#include <M5Cardputer.h>
#if RADAR_ADV
#include <utility/Keyboard/KeyboardReader/TCA8418.h>
#else
#include <utility/Keyboard/KeyboardReader/IOMatrix.h>
#endif
#include "DisplayUi.h"
#include "CardputerIndicators.h"
#include "GroveGps.h"
#include "DiagnosticLog.h"
#include "WpsProbeRadio.h"
#include <freertos/task.h>
#include <esp_timer.h>

namespace {
radar::WifiScanner scanner;
radar::AccessPointStore store;
radar::PcapRing pcap;
radar::AdvertisementCache context;
radar::AdvertisementParser parser;
radar::Exporter exporter;
radar::DisplayUi ui;
radar::CardputerIndicators indicatorHardware;
radar::FieldIndicators indicators(indicatorHardware);
radar::GroveGps gpsInput;
radar::GpsTracker gps(gpsInput);
radar::DiagnosticLog diagnostics;
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
    Serial.begin(115200); Serial.setTxTimeoutMs(0);
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
    ui.attachIndicators(indicators); ui.attachGps(gps);
#if RADAR_WPS_PROBE
    ui.attachProbe(probe);
#endif
    exporter.mount(); scannerReady = displayReady && scanner.begin();
    diagnostics.format("Broadcom Radar %s; %s; %s; heap=%u\n", radar::kFirmwareVersion, hardware,
                  RADAR_WPS_PROBE ? "experimental manual WPS probe" : "passive-only", ESP.getFreeHeap());
    if (!scannerReady) {
        M5Cardputer.Display.fillScreen(TFT_BLACK);
        M5Cardputer.Display.setTextFont(1);
        M5Cardputer.Display.setTextSize(1.5f);
        M5Cardputer.Display.setTextWrap(true);
        M5Cardputer.Display.setCursor(0, 0);
        M5Cardputer.Display.printf("BRCM-RDR %s %s\n\n%s\n%s\n\nRestart to retry", radar::kFirmwareVersion,
                                  radar::kFirmwareVariant, displayReady ? "Wi-Fi init failed" : "Display init failed",
                                  displayReady ? scanner.error() : "Display buffer unavailable");
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
    scanner.tick(); gps.tick(esp_timer_get_time());
    if (!exporter.busy()) for (unsigned i = 0; i < 6 && scanner.pop(frame); ++i) {
#if RADAR_WPS_PROBE
        if (probe.busy()) { probe.receive(frame); continue; }
#endif
        frame.receiver = gps.at(frame.timestampUs);
        radar::Observation observation;
        pcap.add(frame);
        if (parser.parse(frame.bytes, frame.length, frame.rssi, frame.channel, frame.timestampUs, observation)) {
            observation.receiver = frame.receiver;
            if (observation.malformed) ++malformed;
            const auto* ap = store.observe(observation);
            auto stats = scanner.stats();
            if (!observation.malformed) indicators.observe(ap ? ap->info : observation, stats.startedUs);
            context.remember(frame, observation, stats.startedUs);
            if (exporter.needsDetection(observation, ap, stats.nowUs)) {
                const bool running = stats.running;
                if (running && !scanner.setRunning(false)) continue;
                stats = scanner.stats();
                stats.rejected = rejected; stats.malformed = malformed; stats.storeDrops = store.dropped(); stats.storeReplacements = store.replacements();
                exporter.saveDetection(observation, ap, frame, stats, hardware, context.companion(frame));
                if (running) scanner.setRunning(true);
                ui.notify(exporter.message());
            }
        } else ++rejected;
    }
#if RADAR_WPS_PROBE
    if (probeRadio.tick(probe, scanner, exporter, frame, hardware)) ui.notify(exporter.message());
#endif
    ui.tick(store, scanner, exporter, pcap, rejected, malformed, hardware);
    const radar::AccessPoint* selected = ui.selection(store);
#if RADAR_WPS_PROBE
    if (probe.busy()) selected = nullptr;
#endif
    indicators.tick(scanner.stats(), selected, ui.rgbPowerAvailable(), millis());
    static uint32_t lastHealth = 0;
    if (millis() - lastHealth >= 5000) {
        const auto stats = scanner.stats();
        diagnostics.format("uptime_ms=%u heap=%u min_heap=%u aps=%u rx=%u queue_drops=%u store_drops=%u stack_min_bytes=%u\n",
                      unsigned(millis()), ESP.getFreeHeap(), ESP.getMinFreeHeap(), unsigned(store.size()), stats.received, stats.queueDrops, store.dropped(), unsigned(uxTaskGetStackHighWaterMark(nullptr) * sizeof(StackType_t)));
        lastHealth = millis();
    }
    diagnostics.tick(Serial);
    delay(2);
}
