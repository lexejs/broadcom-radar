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
    enum class Screen { List, Detail, Channel, Help, ProbeConfirm, Probe };
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
    void value(int row, const char* name, const Text& text);
    void detail(const AccessPoint& ap, uint64_t nowUs);
    Screen screen_ = Screen::List;
    uint8_t ordered_[kMaxAps]{};
    size_t orderedCount_ = 0;
    size_t selected_ = 0;
    unsigned page_ = 0, channelChoice_ = 0;
    uint32_t lastDraw_ = 0, noticeUntil_ = 0;
    bool resumeAfterExport_ = false;
    char notice_[64] = "";
#if RADAR_WPS_PROBE
    WpsProbe* probe_ = nullptr;
    Observation probeTarget_;
#endif
};
}
