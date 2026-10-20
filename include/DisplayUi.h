#pragma once
#include "Export.h"
#include "WifiScanner.h"
#include <M5Cardputer.h>
namespace radar {
class DisplayUi {
public:
    bool begin();
    void notify(const char* message);
#if RADAR_WPS_PROBE
    void attachProbe(WpsProbe& probe) { probe_ = &probe; }
#endif
    void tick(AccessPointStore& store, WifiScanner& scanner, Exporter& exporter,
              PcapRing& ring, uint32_t& rejected, uint32_t& malformed, const char* hardware);
private:
    enum class Screen { List, Detail, Channel, Country, Help, Text, Diagnostics, Display, ProbeConfirm, Probe };
    enum class Filter { All, Wps, BroadcomWps };
    struct Row {
        char text[27]{};
        uint16_t foreground = TFT_WHITE, background = TFT_BLACK;
    };
    M5Canvas canvas_{&M5Cardputer.Display};
    Row rows_[9]{}, shown_[9]{};
    uint16_t foreground_ = TFT_WHITE, background_ = TFT_BLACK;
    bool firstDraw_ = true, dirty_ = true;
    void updateOrder(const AccessPointStore& store);
    void draw(const AccessPointStore& store, const ScanStats& stats, const Exporter& exporter, const PcapRing& ring);
    void line(int row, const char* format, ...);
    void value(int row, const char* name, const Text& text, bool selected = false);
    void detail(const AccessPoint& ap, const ScanStats& stats);
    void openText(const AccessPoint& ap);
    void textPage();
    void help(const ScanStats& stats, const PcapRing& ring);
    bool setRunning(WifiScanner& scanner, bool running);
    void scannerError(const WifiScanner& scanner);
    void blankScreen();
    void wakeScreen();
    Screen screen_ = Screen::List;
    Screen helpReturn_ = Screen::List, modalReturn_ = Screen::List, diagnosticsReturn_ = Screen::List;
    Screen displayReturn_ = Screen::List;
    Filter filter_ = Filter::All;
    bool signalSort_ = false;
    uint8_t ordered_[kMaxAps]{};
    size_t orderedCount_ = 0;
    size_t selected_ = 0;
    unsigned page_ = 0, channelChoice_ = 0, helpPage_ = 0, field_ = 0, textPage_ = 0;
    uint32_t lastDraw_ = 0, noticeUntil_ = 0, clearUntil_ = 0;
    uint32_t seenScanErrors_ = 0;
    uint32_t lastInput_ = 0;
    unsigned brightnessChoice_ = 3, idleChoice_ = 0, displayField_ = 0;
    size_t countryChoice_ = 0;
    uint8_t firstAllowed_ = 1, lastAllowed_ = 13;
    bool displayOn_ = true, consumeWakeKey_ = false;
    bool resumeAfterExport_ = false;
    char notice_[64] = "";
    char channelError_[64] = "", scannerError_[64] = "";
    char fullText_[257] = "";
    const char* textTitle_ = "SSID";
    size_t textBytes_ = 0;
    bool textLimited_ = false, textObserved_ = false;
#if RADAR_WPS_PROBE
    WpsProbe* probe_ = nullptr;
    Observation probeTarget_;
    bool probeDetails_ = false;
#endif
};
}
