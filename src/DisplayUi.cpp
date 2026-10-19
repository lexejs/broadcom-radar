#include "DisplayUi.h"
#include <cstdarg>
#include <cstdio>
#include <cstring>
namespace radar {
namespace {
constexpr unsigned kPages = 7;
constexpr int kRowHeight = 15;
constexpr size_t kVisibleNetworks = 5;
constexpr Classification kDetectionOrder[] = {Classification::BroadcomSignature, Classification::WpsOnly,
                                             Classification::NoSignature, Classification::InsufficientData};
const char* badge(Classification status) {
    switch (status) {
        case Classification::BroadcomSignature: return "BRCM";
        case Classification::WpsOnly: return "WPS";
        case Classification::NoSignature: return "NONE";
        default: return "WAIT";
    }
}
}
bool DisplayUi::begin() {
    M5Cardputer.Display.setRotation(1);
    M5Cardputer.Display.setBrightness(100);
    canvas_.setColorDepth(16);
    canvas_.setPsram(false);
    if (!canvas_.createSprite(240, kRowHeight)) return false;
    canvas_.setTextFont(1);
    canvas_.setTextSize(1.5f);
    canvas_.setTextWrap(false);
    return true;
}
void DisplayUi::line(int row, const char* format, ...) {
    if (row < 0 || row >= 9) return;
    auto& target = rows_[row];
    va_list args; va_start(args, format); std::vsnprintf(target.text, sizeof(target.text), format, args); va_end(args);
    target.foreground = foreground_; target.background = background_;
}
void DisplayUi::value(int row, const char* name, const Text& text) {
    char rendered[257]; renderBytes(text.data, text.length, rendered, sizeof(rendered));
    line(row, "%s: %s%s", name, text.length ? rendered : "Unknown", text.truncated ? "..." : "");
}
void DisplayUi::updateOrder(const AccessPointStore& store) {
    const size_t selectedIndex = selected_ < orderedCount_ ? ordered_[selected_] : kMaxAps;
    orderedCount_ = selected_ = 0;
    for (auto status : kDetectionOrder) {
        for (size_t i = 0; i < store.size(); ++i) {
            if (classify(store.at(i)) != status) continue;
            if (i == selectedIndex) selected_ = orderedCount_;
            ordered_[orderedCount_++] = static_cast<uint8_t>(i);
        }
    }
}
void DisplayUi::detail(const AccessPoint& ap, uint64_t nowUs) {
    const auto& a = ap.info;
    char ssid[129], mac[18]; renderBytes(a.ssid.data, a.ssid.length, ssid, sizeof(ssid)); renderMac(a.bssid, mac, sizeof(mac));
    line(0, "AP INFO %u/%u %s", page_ + 1, kPages, classificationLabel(classify(ap)));
    foreground_ = TFT_WHITE; background_ = TFT_BLACK;
    line(1, "%s", hiddenSsid(a.ssid) ? "<hidden>" : ssid);
    if (page_ == 0) {
        if (std::strlen(ssid) > 26 && !hiddenSsid(a.ssid)) line(2, "%s", ssid + 26);
        line(3, "%s", mac);
        line(4, "Signal:%d  Max:%d dBm", a.rssi, ap.maxRssi);
        line(5, "Channel:%u  WPS:%s", a.channel, wpsStateName(wpsState(ap)));
        value(6, "Maker", a.wps.manufacturer); value(7, "Model", a.wps.modelName);
    } else if (page_ == 1) {
        line(2, "WHY: %s", classificationLabel(classify(ap)));
        if (a.evidence) {
            line(3, "Broadcom IE: %s", a.evidence & ProprietaryIe ? "YES" : "--");
            line(4, "Fixed UUID:  %s", a.evidence & FixedUuid ? "YES" : "--");
            line(5, "WPS defaults:%s", a.evidence & IdentityDefaults ? "YES (2+ fields)" : "--");
        } else if (!ap.completeAdvertisements) {
            line(3, "Incomplete advertisement"); line(4, "Malformed IE or WPS data");
        } else {
            line(3, a.wpsAdvertised ? "WPS seen, no Broadcom ID" : "No signature observed");
            line(4, "Missing ID != safe");
        }
        line(6, "Passive signatures only"); line(7, "No vulnerability proof");
    } else if (page_ == 2) {
        value(2, "Maker", a.wps.manufacturer); value(3, "Model", a.wps.modelName);
        value(4, "Model #", a.wps.modelNumber); value(5, "Device", a.wps.deviceName);
        value(6, "Serial", a.wps.serialNumber); line(7, "WPS defaults mask: 0x%02X", a.wps.defaults);
    } else if (page_ == 3) {
        auto uuid = [&](int row, const char* name, const Bytes<16>& bytes) {
            char hex[33]{};
            for (size_t i = 0; i < bytes.length; ++i) std::snprintf(hex + i * 2, sizeof(hex) - i * 2, "%02X", bytes.data[i]);
            line(row, "%s: %.16s", name, bytes.length ? hex : "Unknown");
            if (bytes.length > 8) line(row + 1, "        %s", hex + 16);
        };
        uuid(2, "UUID-E", a.wps.uuidE); uuid(4, "UUID-R", a.wps.uuidR);
        line(6, "Capabilities: 0x%04X", a.capabilities);
        line(7, "Valid:%u Bad:%u", ap.completeAdvertisements, ap.malformedAdvertisements);
    } else if (page_ == 4) {
        line(2, "Advertisements: %u", ap.advertisements);
        line(3, "Beacons: %u", ap.beacons); line(4, "Probe responses: %u", ap.probeResponses);
        line(5, "Valid: %u", ap.completeAdvertisements); line(6, "Malformed: %u", ap.malformedAdvertisements);
        line(7, "Last seen: %llus ago", (unsigned long long)((nowUs - ap.lastSeenUs) / 1000000));
    } else {
        line(2, "Vendor IEs %u/2%s", page_ - 4, a.vendorOverflow ? " (limited)" : "");
        const size_t start = (page_ - 5) * 4;
        for (size_t i = start; i < a.vendorCount && i < start + 4; ++i) {
            const auto& v = a.vendors[i];
            line(3 + i - start, "%02X%02X%02X%02X len=%u", v.prefix[0], v.prefix[1], v.prefix[2], v.prefix[3], v.length);
        }
    }
    foreground_ = TFT_CYAN; line(8, "Left/Right:page Esc:back");
}
void DisplayUi::draw(const AccessPointStore& store, const ScanStats& s, const Exporter& ex, const PcapRing& ring) {
    for (auto& row : rows_) row = Row{};
    foreground_ = TFT_WHITE; background_ = TFT_NAVY;
#if RADAR_WPS_PROBE
    if (probe_ && (screen_ == Screen::ProbeConfirm || screen_ == Screen::Probe)) {
        const auto& target = screen_ == Screen::ProbeConfirm ? probeTarget_ : probe_->target();
        char ssid[129], mac[18]; renderBytes(target.ssid.data, target.ssid.length, ssid, sizeof(ssid)); renderMac(target.bssid, mac, sizeof(mac));
        line(0, RADAR_DRIVER_COMPAT ? "WPS TRANSPORT TEST" : "EXPERIMENTAL WPS TEST"); foreground_ = TFT_WHITE; background_ = TFT_BLACK;
        line(1, "%s", ssid); line(2, "%s CH:%u", mac, target.channel);
        if (screen_ == Screen::ProbeConfirm) {
            line(3, "Active test of ONE AP"); line(4, "Use on your own AP only");
            line(5, RADAR_DRIVER_COMPAT ? "Stop at WSC Start" : "Stock driver may reject TX");
            line(6, RADAR_DRIVER_COMPAT ? "Experimental driver mode" : "Uncalibrated fingerprint");
            foreground_ = TFT_CYAN; line(8, "Enter:start Esc:cancel");
        } else {
            const auto& r = probe_->result();
            line(3, "%s", probe_->busy() ? probeStageName(r.stage) : r.reason == ProbeReason::TransportReady ? "WSC START RECEIVED" : probeVerdictName(r.verdict));
            line(4, "%s", probeReasonName(r.reason));
            line(5, "TX:%u Frames:%u Err:%x", r.txAccepted, unsigned(probe_->recordCount()), unsigned(r.driverError));
            line(6, "Ads:%u NoWPS:%u RX:%u", unsigned(r.advertisements), unsigned(r.noWps), unsigned(r.scanRxFrames));
            if (probe_->done()) line(7, "%s", r.reported && !r.restored ? "Scan restore FAILED" : ex.message());
            foreground_ = TFT_CYAN; line(8, probe_->busy() ? "Esc:cancel test" : "E:save report Esc:back");
        }
    } else
#endif
    if (screen_ == Screen::Detail && selected_ < orderedCount_) detail(store.at(ordered_[selected_]), s.nowUs);
    else if (screen_ == Screen::Help) {
        line(0, "KEYBOARD HELP"); foreground_ = TFT_WHITE; background_ = TFT_BLACK;
        line(1, "; . , / : move / page"); line(2, "Enter: open / next / apply");
        line(3, "S: pause / resume scan"); line(4, "M: hop / hold channel");
        line(5, "E: save JSON / CSV / PCAP"); line(6, "P: PCAP %s (last %u)", ring.enabled() ? "ON" : "OFF", unsigned(kPcapDepth));
        line(7, "R:clear Drop:%u", s.queueDrops + store.dropped()); foreground_ = TFT_CYAN;
#if RADAR_WPS_PROBE
        line(8, "T:WPS test  Esc:back");
#else
        line(8, "Esc: back to networks");
#endif
    } else if (screen_ == Screen::Channel) {
        line(0, "CHANNEL MODE"); foreground_ = TFT_WHITE; background_ = TFT_BLACK;
        line(1, "Country:%s  Channels:1-%u", RADAR_COUNTRY, s.channelCount);
        if (!channelChoice_) line(3, "> HOP: all channels");
        else line(3, "> HOLD: channel %02u", channelChoice_);
        line(4, "Hop dwell: %u ms", kDwellMs);
        line(6, "Arrows: choose mode / CH"); line(7, "Enter: apply selection");
        foreground_ = TFT_CYAN; line(8, "Esc: cancel");
    } else {
#if RADAR_WPS_PROBE
        line(0, "BROADCOM RADAR TEST"); background_ = TFT_BLACK;
#else
        line(0, "BROADCOM RADAR"); background_ = TFT_BLACK;
#endif
        line(1, "%s %s CH:%02u B:%d%%", s.running ? "RUNNING" : "PAUSED", s.hopping ? "HOP" : "FIX", s.channel, M5Cardputer.Power.getBatteryLevel());
        line(2, "AP:%u/%u BRCM:%u SD:%s", unsigned(store.size()), unsigned(kMaxAps), unsigned(store.broadcomCount()), ex.available() ? "OK" : "--");
        const size_t top = selected_ >= kVisibleNetworks ? selected_ - kVisibleNetworks + 1 : 0;
        if (!store.size()) line(4, "Listening for networks...");
        for (size_t i = top; i < orderedCount_ && i < top + kVisibleNetworks; ++i) {
            const auto& ap = store.at(ordered_[i]); auto status = classify(ap); char ssid[129];
            renderBytes(ap.info.ssid.data, ap.info.ssid.length, ssid, sizeof(ssid));
            foreground_ = status == Classification::BroadcomSignature ? TFT_ORANGE : TFT_WHITE;
            background_ = i == selected_ ? TFT_NAVY : TFT_BLACK;
            line(3 + i - top, "%c%-4s %-11.11s %4d dBm", i == selected_ ? '>' : ' ', badge(status), hiddenSsid(ap.info.ssid) ? "<hidden>" : ssid, ap.info.rssi);
        }
        foreground_ = TFT_CYAN; background_ = TFT_BLACK;
        if (ex.busy() || int32_t(noticeUntil_ - millis()) > 0) line(8, "%s", notice_[0] ? notice_ : ex.message());
        else line(8, "S:%s M:channel H:help", s.running ? "pause" : "run");
    }
    for (int i = 0; i < 9; ++i) {
        const auto& row = rows_[i]; auto& shown = shown_[i];
        if (!firstDraw_ && row.foreground == shown.foreground && row.background == shown.background && !std::strcmp(row.text, shown.text)) continue;
        canvas_.fillScreen(row.background);
        canvas_.setTextColor(row.foreground, row.background); canvas_.setCursor(0, 1); canvas_.print(row.text);
        canvas_.pushSprite(0, i * kRowHeight);
        M5Cardputer.Display.waitDMA();
        shown = row;
    }
    firstDraw_ = false;
}
void DisplayUi::notify(const char* message) {
    std::snprintf(notice_, sizeof(notice_), "%s", message);
    noticeUntil_ = millis() + 5000; dirty_ = true;
}
void DisplayUi::tick(AccessPointStore& store, WifiScanner& scanner, Exporter& exporter,
                     PcapRing& ring, uint32_t& rejected, uint32_t& malformed, const char* hardware) {
    bool exporting = exporter.busy(); exporter.tick();
    if (exporting && !exporter.busy()) {
        std::snprintf(notice_, sizeof(notice_), "%s", exporter.message()); noticeUntil_ = millis() + 5000;
        if (resumeAfterExport_) scanner.setRunning(true);
    }
    updateOrder(store);
    auto& keyboard = M5Cardputer.Keyboard;
    if (keyboard.isChange() && keyboard.isPressed()) {
        dirty_ = true;
        const auto& keys = keyboard.keysState();
        const bool up = keys.up || keyboard.isKeyPressed(';');
        const bool down = keys.down || keyboard.isKeyPressed('.');
        const bool left = keys.left || keyboard.isKeyPressed(',');
        const bool right = keys.right || keyboard.isKeyPressed('/');
        const bool esc = keys.esc || keys.backspace || keyboard.isKeyPressed('`');
#if RADAR_WPS_PROBE
        if (probe_ && (screen_ == Screen::ProbeConfirm || screen_ == Screen::Probe)) {
            if (esc) {
                if (probe_->busy()) probe_->cancel(scanner.stats().nowUs);
                else screen_ = Screen::List;
            } else if (screen_ == Screen::ProbeConfirm && keys.enter) {
                if (probe_->request(probeTarget_)) screen_ = Screen::Probe;
                else { notify("Need named WPS AP + channel"); screen_ = Screen::List; }
            } else if (screen_ == Screen::Probe && probe_->done()) {
                for (char c : keys.word) if (c == 'e' || c == 'E') {
                    const bool running = scanner.stats().running;
                    if (!running || scanner.setRunning(false)) {
                        exporter.saveProbe(*probe_, hardware);
                        if (running) scanner.setRunning(true);
                    }
                }
            }
            draw(store, scanner.stats(), exporter, ring); lastDraw_ = millis(); dirty_ = false; return;
        }
#endif
        if (esc) screen_ = Screen::List;
        else if (screen_ == Screen::Channel) {
            unsigned choices = scanner.stats().channelCount + 1;
            if (up || left) channelChoice_ = (channelChoice_ + choices - 1) % choices;
            if (down || right) channelChoice_ = (channelChoice_ + 1) % choices;
            if (keys.enter && !exporter.busy()) { scanner.selectChannel(channelChoice_); screen_ = Screen::List; }
        } else if (screen_ == Screen::Detail && (left || right || keys.enter)) page_ = (page_ + (left ? kPages - 1 : 1)) % kPages;
        else if (screen_ == Screen::List) {
            if ((up || left) && selected_) --selected_;
            if ((down || right) && selected_ + 1 < store.size()) ++selected_;
            if (keys.enter && store.size()) { screen_ = Screen::Detail; page_ = 0; }
        }
        for (char c : keys.word) {
            if (exporter.busy()) break;
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
#if RADAR_WPS_PROBE
            if (c == 't' && probe_ && (screen_ == Screen::List || screen_ == Screen::Detail) && selected_ < orderedCount_) {
                probeTarget_ = store.at(ordered_[selected_]).info; screen_ = Screen::ProbeConfirm; break;
            }
#endif
            if (c == 'h') screen_ = screen_ == Screen::Help ? Screen::List : Screen::Help;
            if (c == 's') scanner.setRunning(!scanner.stats().running);
            if (c == 'r') {
                const bool running = scanner.stats().running;
                if (running && !scanner.setRunning(false)) continue;
                store.clear(); ring.clear(); scanner.clear(); rejected = malformed = 0; selected_ = orderedCount_ = 0; screen_ = Screen::List;
                if (running) scanner.setRunning(true);
            }
            if (c == 'm') { channelChoice_ = scanner.stats().hopping ? 0 : scanner.stats().channel; screen_ = Screen::Channel; }
            if (c == 'p') ring.enable(!ring.enabled());
            if (c == 'e') {
                resumeAfterExport_ = scanner.stats().running;
                if (resumeAfterExport_ && !scanner.setRunning(false)) continue;
                auto stats = scanner.stats(); stats.rejected = rejected; stats.malformed = malformed; stats.storeDrops = store.dropped();
                if (!exporter.start(store, stats, ring, hardware) && resumeAfterExport_) scanner.setRunning(true);
                std::snprintf(notice_, sizeof(notice_), "%s", exporter.message()); noticeUntil_ = millis() + 5000;
                screen_ = Screen::List;
            }
        }
    }
    if (dirty_ || millis() - lastDraw_ >= 500) {
        draw(store, scanner.stats(), exporter, ring); lastDraw_ = millis(); dirty_ = false;
    }
}
}
