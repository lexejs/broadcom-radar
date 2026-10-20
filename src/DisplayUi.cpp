#include "DisplayUi.h"
#include <cstdarg>
#include <cstdio>
#include <cstring>
namespace radar {
namespace {
constexpr unsigned kPages = 7, kHelpPages = 5;
constexpr uint8_t kBrightness[] = {30, 50, 70, 100, 150, 200, 255};
constexpr uint16_t kIdleSeconds[] = {0, 30, 60, 120, 300};
constexpr int kRowHeight = 15;
constexpr size_t kVisibleNetworks = 5, kColumns = 26;
constexpr const char* kDetectionBadges[] = {"BRCM+WPS", "BRCM", "WPS", "NONE", "WAIT"};
constexpr const char* kPageNames[] = {"SUMMARY", "EVIDENCE", "IDENTITY", "UUID", "ACTIVITY", "VENDOR IEs 1/2", "VENDOR IEs 2/2"};
size_t detectionGroup(const AccessPoint& ap) {
    switch (classify(ap)) {
        case Classification::BroadcomSignature: return wpsState(ap) == WpsState::Yes ? 0 : 1;
        case Classification::WpsOnly: return 2;
        case Classification::NoSignature: return 3;
        default: return 4;
    }
}
const char* ssidText(const Observation& ap, char* rendered, size_t capacity) {
    if (!ap.ssidPresent) return "<not observed>";
    if (hiddenSsid(ap.ssid)) return "<hidden>";
    renderBytes(ap.ssid.data, ap.ssid.length, rendered, capacity); return rendered;
}
const char* sourceLabel(uint8_t sources) {
    return sources == 3 ? "B+P" : sources == 1 ? "B" : sources == 2 ? "P" : "--";
}
// renderBytes emits only ASCII or complete four-character escape tokens.
size_t segmentLength(const char* text, size_t columns) {
    size_t size = 0;
    while (text[size]) {
        const size_t token = text[size] == '\\' ? 4 : 1;
        if (size + token > columns) break;
        size += token;
    }
    return size;
}
#if RADAR_WPS_PROBE
const char* stageLabel(ProbeStage stage) {
    switch (stage) {
        case ProbeStage::Requested: return "Preparing test";
        case ProbeStage::Advertisement: return "Checking fresh AP data";
        case ProbeStage::Authentication: return "Waiting for authentication";
        case ProbeStage::Association: return "Waiting for association";
        case ProbeStage::Identity: return "Waiting for EAP identity";
        case ProbeStage::Start: return "Waiting for WPS start";
        case ProbeStage::Differential: return "Waiting for WPS reply";
        case ProbeStage::Cleanup: return "Closing test session";
        case ProbeStage::Restore: return "Restoring scan reception";
        default: return "Test finished";
    }
}
const char* reasonLabel(ProbeReason reason, ProbeResponse response) {
    switch (reason) {
        case ProbeReason::Response:
            return response == ProbeResponse::FragmentAck ? "Reply: WPS fragment ACK" :
                   response == ProbeResponse::EapFailure ? "Reply: EAP failure" : "Reply: disconnect code 0";
        case ProbeReason::NoWps: return "WPS not observed";
        case ProbeReason::Timeout: return "No reply before timeout";
        case ProbeReason::ApRejected: return "AP rejected the session";
        case ProbeReason::UnexpectedEap: return "Unexpected EAP reply";
        case ProbeReason::DriverRejected: return "Driver refused TX";
        case ProbeReason::Cancelled: return "Cancelled by user";
        case ProbeReason::TraceFull: return "Trace buffer full";
        case ProbeReason::RadioSetupFailed: return "Radio setup failed";
        case ProbeReason::TransportReady: return "WPS start received";
        case ProbeReason::InvalidAdvertisement: return "AP data changed or invalid";
        default: return "No family result";
    }
}
#endif
}
const AccessPoint* DisplayUi::selection(const AccessPointStore& store) const {
    return selected_ < orderedCount_ && ordered_[selected_] < store.size() ? &store.at(ordered_[selected_]) : nullptr;
}
bool DisplayUi::rgbPowerAvailable() const {
#if RADAR_ADV
    return displayOn_ && kBrightness[brightnessChoice_] == 255;
#else
    return true;
#endif
}
bool DisplayUi::begin() {
    M5Cardputer.Display.setRotation(1);
    M5Cardputer.Display.setBrightness(kBrightness[brightnessChoice_]);
    lastInput_ = millis();
    canvas_.setColorDepth(16); canvas_.setPsram(false);
    if (!canvas_.createSprite(240, kRowHeight)) return false;
    canvas_.setTextFont(1); canvas_.setTextSize(1.5f); canvas_.setTextWrap(false);
    return true;
}
void DisplayUi::line(int row, const char* format, ...) {
    if (row < 0 || row >= 9) return;
    auto& target = rows_[row];
    char formatted[384];
    va_list args; va_start(args, format);
    const int length = std::vsnprintf(formatted, sizeof(formatted), format, args); va_end(args);
    const size_t size = segmentLength(formatted, length > int(kColumns) ? kColumns - 3 : kColumns);
    std::memcpy(target.text, formatted, size);
    std::snprintf(target.text + size, sizeof(target.text) - size, "%s", length > int(kColumns) ? "..." : "");
    target.foreground = foreground_; target.background = background_;
}
void DisplayUi::value(int row, const char* name, const Text& text, bool selected) {
    char rendered[257]; renderBytes(text.data, text.length, rendered, sizeof(rendered));
    background_ = selected ? TFT_NAVY : TFT_BLACK;
    line(row, "%s: %s%s", name, text.length ? rendered : "Not observed", text.truncated ? "..." : "");
    background_ = TFT_BLACK;
}
void DisplayUi::updateOrder(const AccessPointStore& store) {
    const size_t selectedIndex = selected_ < orderedCount_ ? ordered_[selected_] : kMaxAps;
    orderedCount_ = selected_ = 0;
    for (size_t group = 0; group < sizeof(kDetectionBadges) / sizeof(kDetectionBadges[0]); ++group) {
        const size_t start = orderedCount_;
        for (size_t i = 0; i < store.size(); ++i) {
            const auto& ap = store.at(i);
            if (filter_ != Filter::All && wpsTargetError(ap.info)) continue;
            if (filter_ != Filter::All && (ap.info.channel < firstAllowed_ || ap.info.channel > lastAllowed_)) continue;
            if (filter_ == Filter::BroadcomWps && classify(ap) != Classification::BroadcomSignature) continue;
            if (detectionGroup(ap) != group) continue;
            size_t position = orderedCount_++;
            while (position > start) {
                const auto& previous = store.at(ordered_[position - 1]);
                const bool after = signalSort_ && previous.info.rssi != ap.info.rssi ?
                    previous.info.rssi < ap.info.rssi : previous.discoveryOrder > ap.discoveryOrder;
                if (!after) break;
                ordered_[position] = ordered_[position - 1]; --position;
            }
            ordered_[position] = static_cast<uint8_t>(i);
        }
    }
    for (size_t i = 0; i < orderedCount_; ++i) if (ordered_[i] == selectedIndex) selected_ = i;
}
void DisplayUi::detail(const AccessPoint& ap, const ScanStats& stats) {
    const auto& a = ap.info;
    char rendered[129], mac[18]; const char* ssid = ssidText(a, rendered, sizeof(rendered));
    renderMac(a.bssid, mac, sizeof(mac));
    line(0, "%u/%u %s", page_ + 1, kPages, kPageNames[page_]);
    foreground_ = TFT_WHITE; background_ = field_ == 0 ? TFT_NAVY : TFT_BLACK;
    if (page_ == 0) {
        const size_t first = segmentLength(ssid, kColumns);
        line(1, "%.*s", int(first), ssid);
        if (ssid[first]) {
            const size_t second = segmentLength(ssid + first, kColumns);
            if (ssid[first + second]) {
                const size_t clipped = segmentLength(ssid + first, kColumns - 3);
                line(2, "%.*s...", int(clipped), ssid + first);
            } else line(2, "%s", ssid + first);
        }
    } else line(1, "%s", ssid);
    background_ = TFT_BLACK;
    if (page_ == 0) {
        line(3, "%s", mac);
        line(4, "Signal:%d Max:%d dBm", a.rssi, ap.maxRssi);
        line(5, "Channel:%u WPS:%s", a.channel, wpsState(ap) == WpsState::No ? "not seen" : wpsStateName(wpsState(ap)));
        value(6, "Maker", a.wps.manufacturer, field_ == 1); value(7, "Model", a.wps.modelName, field_ == 2);
        line(8, "%s Last:%llus", kDetectionBadges[detectionGroup(ap)],
             (unsigned long long)((stats.nowUs - ap.lastSeenUs) / 1000000));
    } else if (page_ == 1) {
        line(2, "Observed: %s", kDetectionBadges[detectionGroup(ap)]);
        if (a.evidence) {
            line(3, "Broadcom IE: %s [%s]", a.evidence & ProprietaryIe ? "YES" : "--", sourceLabel(evidenceFrameSources(ap, ProprietaryIe)));
            line(4, "Fixed UUID: %s [%s]", a.evidence & FixedUuid ? "YES" : "--", sourceLabel(evidenceFrameSources(ap, FixedUuid)));
            line(5, "Defaults: %s [%s]", a.evidence & IdentityDefaults ? "2+ fields" : "--", sourceLabel(a.evidence & IdentityDefaults ? evidenceFrameSources(ap, IdentityDefaults) : 0));
        } else if (!ap.completeAdvertisements) {
            line(3, "Incomplete advertisement"); line(4, "Malformed IE or WPS data");
        } else {
            line(3, a.wpsAdvertised ? "WPS seen, no Broadcom ID" : "No signature observed");
            line(4, "Missing ID != safe");
        }
        line(6, "Observed this session"); line(7, "No vulnerability proof");
        line(8, "AP patch status unknown");
    } else if (page_ == 2) {
        value(2, "Maker", a.wps.manufacturer, field_ == 1); value(3, "Model", a.wps.modelName, field_ == 2);
        value(4, "Model #", a.wps.modelNumber, field_ == 3); value(5, "Device", a.wps.deviceName, field_ == 4);
        value(6, "Serial", a.wps.serialNumber, field_ == 5); line(7, "Defaults mask: 0x%02X", a.wps.defaults);
        line(8, "WPS-advertised identity");
    } else if (page_ == 3) {
        auto uuid = [&](int row, const char* name, const Bytes<16>& bytes) {
            char hex[33]{};
            for (size_t i = 0; i < bytes.length; ++i) std::snprintf(hex + i * 2, sizeof(hex) - i * 2, "%02X", bytes.data[i]);
            line(row, "%s: %.16s", name, bytes.length ? hex : "Not observed");
            if (bytes.length > 8) line(row + 1, "        %s", hex + 16);
        };
        uuid(2, "UUID-E", a.wps.uuidE); uuid(4, "UUID-R", a.wps.uuidR);
        line(6, "Capabilities: 0x%04X", a.capabilities);
        line(7, "Valid:%u Bad:%u", ap.completeAdvertisements, ap.malformedAdvertisements);
        line(8, "Raw advertised values");
    } else if (page_ == 4) {
        line(2, "Advertisements: %u", ap.advertisements);
        line(3, "Beacons: %u", ap.beacons); line(4, "Probe responses: %u", ap.probeResponses);
        line(5, "Valid:%u Bad:%u", ap.completeAdvertisements, ap.malformedAdvertisements);
        line(6, "Last seen: %llus ago", (unsigned long long)((stats.nowUs - ap.lastSeenUs) / 1000000));
        line(7, "Capture: %s", stats.running ? "running" : "paused");
        line(8, "Valid sources: %s", sourceLabel(ap.metadataSources));
    } else {
        const size_t start = (page_ - 5) * 4;
        line(2, "Stored: %u of max %u IEs", a.vendorCount, unsigned(sizeof(a.vendors) / sizeof(a.vendors[0])));
        if (a.vendorCount <= start) line(3, start ? "No more vendor IEs" : "No vendor IEs observed");
        for (size_t i = start; i < a.vendorCount && i < start + 4; ++i) {
            const auto& v = a.vendors[i];
            line(3 + i - start, "%02X%02X%02X%02X len=%u", v.prefix[0], v.prefix[1], v.prefix[2], v.prefix[3], v.length);
        }
        line(7, "len: advertised IE bytes");
        line(8, "%s", a.vendorOverflow ? "More IEs omitted (limit 8)" : "All observed IEs retained");
    }
}
void DisplayUi::openText(const AccessPoint& ap) {
    const auto& a = ap.info;
    textTitle_ = "SSID"; textBytes_ = a.ssid.length; textLimited_ = a.ssid.truncated; textObserved_ = a.ssidPresent;
    if (!field_) {
        char rendered[129]; std::snprintf(fullText_, sizeof(fullText_), "%s", ssidText(a, rendered, sizeof(rendered)));
    }
    else {
        const Text* fields[] = {&a.wps.manufacturer, &a.wps.modelName, &a.wps.modelNumber, &a.wps.deviceName, &a.wps.serialNumber};
        const char* names[] = {"Manufacturer", "Model", "Model number", "Device name", "Serial"};
        const auto& field = *fields[field_ - 1]; textTitle_ = names[field_ - 1];
        textBytes_ = field.length; textLimited_ = field.truncated; textObserved_ = field.length != 0;
        if (field.length) renderBytes(field.data, field.length, fullText_, sizeof(fullText_));
        else std::snprintf(fullText_, sizeof(fullText_), "Not observed");
    }
    textPage_ = 0; screen_ = Screen::Text;
}
void DisplayUi::textPage() {
    size_t offset = 0, pages = 1, starts[3]{};
    for (size_t row = 0; fullText_[offset]; ++row) {
        if (row && row % 7 == 0) starts[pages++] = offset;
        offset += segmentLength(fullText_ + offset, kColumns);
    }
    if (textPage_ >= pages) textPage_ = unsigned(pages - 1);
    line(0, "%s %u/%u", textTitle_, textPage_ + 1, unsigned(pages));
    foreground_ = TFT_WHITE; background_ = TFT_BLACK;
    offset = starts[textPage_];
    for (int row = 1; row <= 7 && fullText_[offset]; ++row) {
        const auto size = segmentLength(fullText_ + offset, kColumns);
        line(row, "%.*s", int(size), fullText_ + offset); offset += size;
    }
    if (!textObserved_) line(8, "Value not observed");
    else line(8, "%u bytes; %s", unsigned(textBytes_), textLimited_ ? "source limited" : "complete value");
}
void DisplayUi::help(const ScanStats& s, const PcapRing& ring) {
    if (helpReturn_ == Screen::Indicators) line(0, "INDICATOR HELP");
    else line(0, "HELP %u/%u", helpPage_ + 1, kHelpPages);
    foreground_ = TFT_WHITE; background_ = TFT_BLACK;
    if (helpReturn_ == Screen::Indicators) {
        line(1, "Up/Down: choose indicator"); line(2, "Enter/Left/Right: toggle");
        line(3, "Green: receiver activity"); line(4, "Orange: new signature");
        line(5, "Sound: selected AP RSSI"); line(6, "Stale/paused: no clicks");
        line(7, "Esc: back; defaults OFF");
    } else if (helpPage_ == 0) {
        line(1, "; up . down , left / right"); line(2, "Enter: open / next / apply");
        line(3, "Esc / Backspace / `: back"); line(4, "H: help; Left/Right: page");
        line(5, "F: filter S: pause/resume"); line(6, "M:CH C:country P:PCAP");
        line(7, "O:sort N:alerts");
    } else if (helpPage_ == 1) {
        line(1, "ALL: all stored networks"); line(2, "WPS: test-ready APs");
        line(3, "B+W: BRCM + test-ready"); line(4, "B/P: Beacon/Probe Response");
        line(5, "NONE: no signature seen"); line(6, "WAIT: incomplete AP data");
        line(7, "Hidden rows stay in export");
    } else if (helpPage_ == 2) {
        line(1, "E: export all stored APs"); line(2, "J/C/P: JSON / CSV / PCAP");
        line(3, "/broadcom-radar/"); line(4, "BRCM auto-saves with PCAP");
#if RADAR_WPS_PROBE
        line(5, "Test report auto-saves");
#else
        line(5, "PCAP stores received ads");
#endif
        line(6, "R twice:clear; SD kept");
        line(7, "PCAP: %s; last %u frames", ring.enabled() ? "ON" : "OFF", unsigned(kPcapDepth));
    } else if (helpPage_ == 3) {
        line(1, "Details: Up/Down field"); line(2, "V: read full selected text");
#if RADAR_WPS_PROBE
        line(3, "T: review one-AP test"); line(4, "Enter: start Esc: cancel");
        line(5, "D: diagnostics / test info"); line(6, "E: retry failed test save");
#else
        line(3, "Passive capture build"); line(4, "D: scan diagnostics");
        line(5, "No active tests available"); line(6, "No vulnerability verdict");
#endif
#if RADAR_WPS_PROBE
        line(7, "A:MAC %s Scan:%s", probe_ && probe_->randomStation() ? "random" : "device", s.running ? "RUN" : "PAUSE");
#else
        line(7, "Capture is %s", s.running ? "running" : "paused");
#endif
    } else {
        line(1, "B: screen settings"); line(2, "L: turn display off");
        line(3, "Any key: wake only"); line(4, "Up/Down: choose setting");
        line(5, "Left/Right: change value"); line(6, "Enter: change / turn off");
        line(7, "Idle timer: keyboard only");
    }
    line(8, "BRCM-RDR %s %s", kFirmwareVersion, kFirmwareVariant);
}
void DisplayUi::draw(const AccessPointStore& store, const ScanStats& s, const Exporter& ex, const PcapRing& ring) {
    for (auto& row : rows_) row = Row{};
    foreground_ = TFT_WHITE; background_ = TFT_NAVY;
#if RADAR_WPS_PROBE
    if (probe_ && (screen_ == Screen::ProbeConfirm || screen_ == Screen::Probe)) {
        const auto& target = screen_ == Screen::ProbeConfirm ? probeTarget_ : probe_->target();
        char rendered[129], mac[18]; const char* ssid = ssidText(target, rendered, sizeof(rendered)); renderMac(target.bssid, mac, sizeof(mac));
        line(0, screen_ == Screen::ProbeConfirm ? (RADAR_DRIVER_COMPAT ? (RADAR_TRANSPORT_ONLY ? "WPS TRANSPORT TEST" : "WPS FINGERPRINT TEST") : "EXPERIMENTAL WPS TEST") : probeDetails_ ? "TEST DIAGNOSTICS" : probe_->busy() ? "WPS TEST IN PROGRESS" : "WPS TEST RESULT");
        foreground_ = TFT_WHITE; background_ = TFT_BLACK;
        line(1, "%s", ssid); line(2, "%s CH:%u", mac, target.channel);
        if (screen_ == Screen::ProbeConfirm) {
            const char* reason = probe_->startError(target);
            if (!reason && (target.channel < firstAllowed_ || target.channel > lastAllowed_)) reason = "Channel outside country";
            if (reason) {
                line(3, "TEST UNAVAILABLE"); line(4, "%s", reason);
                if (!s.running) line(5, "Capture paused; return");
                else if (target.channel < firstAllowed_ || target.channel > lastAllowed_) line(5, "Check country settings");
                else if (!std::strcmp(reason, "Invalid BSSID")) line(5, "Select a valid AP");
                else if (target.malformed) line(5, "Needs complete AP data");
                else if (!target.ssidPresent || hiddenSsid(target.ssid)) line(5, "Needs an observed name");
                else line(5, "Needs observed WPS data");
                line(6, "No packets sent"); line(8, "Capture: %s", s.running ? "running" : "paused");
            } else {
                line(3, "Active test of ONE AP"); line(4, "Use on your own AP only");
                line(5, RADAR_DRIVER_COMPAT ? (RADAR_TRANSPORT_ONLY ? "Stop at WSC Start" : "One empty WPS fragment") : "Stock driver may reject TX");
                line(6, "Enter confirms this AP"); line(7, RADAR_TRANSPORT_ONLY ? "Transport experiment" : "Uncalibrated fingerprint");
                line(8, probe_->randomStation() ? "MAC: random; not sent" : "MAC: device; not sent");
            }
        } else {
            const auto& r = probe_->result();
            if (probeDetails_) {
                line(3, "Stage: %s", probeStageName(probe_->done() ? r.stoppedAt : r.stage));
                line(4, "TX:%u Trace:%u Err:%x", r.txAccepted, unsigned(probe_->recordCount()), unsigned(r.driverError));
                line(5, "Ads:%u NoWPS:%u RX:%u", unsigned(r.advertisements), unsigned(r.noWps), unsigned(r.scanRxFrames));
                line(6, "Queue:%u Oversize:%u", unsigned(r.queueDrops), unsigned(r.oversizeDrops));
                line(7, "Trace lost:%u AP code:%u", r.traceDropped, r.apStatus);
                line(8, "%s", probe_->done() ? ex.probeMessage(*probe_) : "Test runs in background");
            } else if (probe_->busy()) {
                line(3, "%s", stageLabel(r.stage));
                line(4, "Elapsed: %llus", (unsigned long long)(r.startedUs && s.nowUs >= r.startedUs ? (s.nowUs - r.startedUs) / 1000000 : 0));
                line(5, "Matching AP ads: %u", unsigned(r.advertisements));
                line(6, "TX accepted: %u", r.txAccepted);
                line(7, "Experimental test"); line(8, "Uncalibrated; not proof");
            } else {
                line(3, "%s", r.reason == ProbeReason::Cancelled ? "TEST CANCELLED" : r.reason == ProbeReason::TransportReady ? "TRANSPORT READY" :
                     r.verdict == ProbeVerdict::HostapdLike ? "Candidate: hostapd-like" : r.verdict == ProbeVerdict::BroadcomLike ? "Candidate: BRCM-WPS-like" : "Family: undetermined");
                line(4, "%s", reasonLabel(r.reason, r.response));
                line(5, "Uncalibrated; not proof");
                line(6, "%s", !r.reported ? "Scan: restoring" : !r.restored ? "Scan: restore FAILED" : !r.scanWasRunning ? "Scan: restored paused" :
                     !s.running ? (scannerError_[0] ? "Scan: stopped by error" : "Scan: paused after test") : r.scanRxFrames ? "Scan: resumed; RX seen" : "Scan: resumed; RX unseen");
                line(7, "%s", ex.probeMessage(*probe_));
                line(8, "%s", ex.probeSaved(*probe_) ? "JSON + PCAP saved" : "Report not saved yet");
            }
        }
    } else
#endif
    if (screen_ == Screen::Detail && selected_ < orderedCount_) detail(store.at(ordered_[selected_]), s);
    else if (screen_ == Screen::Text) textPage();
    else if (screen_ == Screen::Help) help(s, ring);
    else if (screen_ == Screen::Indicators && indicators_) {
        line(0, "FIELD INDICATORS"); foreground_ = TFT_WHITE; background_ = TFT_BLACK;
        background_ = indicatorField_ == 0 ? TFT_NAVY : TFT_BLACK;
        line(1, "RGB: %s", indicators_->ledEnabled() ? "ON" : "OFF");
        background_ = indicatorField_ == 1 ? TFT_NAVY : TFT_BLACK;
        line(2, "Selected AP sound: %s", indicators_->soundEnabled() ? "ON" : "OFF"); background_ = TFT_BLACK;
        line(4, "Settings reset on restart");
#if RADAR_ADV
        line(5, "ADV RGB needs light 255");
#else
        line(5, "RGB works with screen off");
#endif
        line(6, "Sound waits for fresh AP");
        line(7, "Faster clicks: stronger RX");
        if (indicators_->soundError()) line(8, "Sound unavailable; OFF");
    }
    else if (screen_ == Screen::Display) {
        line(0, "SCREEN SETTINGS"); foreground_ = TFT_WHITE; background_ = TFT_BLACK;
        line(1, "Settings reset on restart");
        background_ = displayField_ == 0 ? TFT_NAVY : TFT_BLACK;
        line(2, "Brightness: %u / 255", kBrightness[brightnessChoice_]);
        background_ = displayField_ == 1 ? TFT_NAVY : TFT_BLACK;
        if (idleChoice_) line(3, "Auto off: %u seconds", kIdleSeconds[idleChoice_]);
        else line(3, "Auto off: disabled");
        background_ = displayField_ == 2 ? TFT_NAVY : TFT_BLACK;
        line(4, "Turn display off"); background_ = TFT_BLACK;
        line(6, "Any key wakes the display"); line(7, "Capture and saves continue");
        line(8, "Timer waits during tests");
    }
    else if (screen_ == Screen::Diagnostics) {
        line(0, "SCAN DIAGNOSTICS"); foreground_ = TFT_WHITE; background_ = TFT_BLACK;
        line(1, "APs stored: %u/%u", unsigned(store.size()), unsigned(kMaxAps));
        line(2, "New AP ads dropped: %u", store.dropped()); line(3, "RX queue drops: %u", s.queueDrops);
        line(4, "Oversize frames: %u", s.oversizeDrops); line(5, "Bad ads:%u Rejected:%u", s.malformed, s.rejected);
        line(6, "PCAP: %u/%u %s", unsigned(ring.size()), unsigned(kPcapDepth), ring.enabled() ? "ON" : "OFF");
        line(7, "Broadcom APs: %u", unsigned(store.broadcomCount()));
        if (scannerError_[0]) line(8, "%s", scannerError_);
        else line(8, "AP replacements: %u", store.replacements());
    } else if (screen_ == Screen::Channel) {
        line(0, "CHANNEL MODE"); foreground_ = TFT_WHITE; background_ = TFT_BLACK;
        line(1, "Country:%s CH:%u-%u", s.country, firstAllowed_, s.channelCount);
        if (s.hopping) line(3, "Current: HOP (CH %02u)", s.channel);
        else line(3, "Current: HOLD CH %02u", s.channel);
        if (!channelChoice_) line(4, "Select: HOP all channels");
        else line(4, "Select: HOLD CH %02u", channelChoice_);
        line(6, "Hop dwell: %u ms", kDwellMs); line(7, "Selection not applied yet");
        line(8, "%s", channelError_[0] ? channelError_ : "Capture keeps current mode");
    } else if (screen_ == Screen::Country) {
        line(0, "COUNTRY SETTINGS"); foreground_ = TFT_WHITE; background_ = TFT_BLACK;
        line(1, "Current: %s (%u-%u)", s.country, firstAllowed_, s.channelCount);
        line(3, "Select: %s", kCountries[countryChoice_]);
        line(4, "01 = world safe profile"); line(5, "Selection not applied yet");
        line(6, "Settings reset on restart");
        line(8, "%s", channelError_[0] ? channelError_ : "Captured records are kept");
    } else {
        const char* filter = filter_ == Filter::All ? "ALL" : filter_ == Filter::Wps ? "WPS" : "B+W";
        line(0, "BRCM-RDR %s %s %s%s", kFirmwareVersion, kFirmwareVariant, filter, signalSort_ ? " RSSI" : ""); background_ = TFT_BLACK;
        line(1, "%s %s C%02u %d%% #%u", s.running ? "RUN" : "PAUSED", s.hopping ? "HOP" : "FIX", s.channel,
             M5Cardputer.Power.getBatteryLevel(), unsigned(orderedCount_ ? selected_ + 1 : 0));
        if (store.size() == kMaxAps) { foreground_ = TFT_ORANGE; line(2, "AP:%u/%u FULL SD:%s", unsigned(orderedCount_), unsigned(store.size()), ex.available() ? "OK" : "--"); }
        else line(2, "AP:%u/%u B:%u SD:%s", unsigned(orderedCount_), unsigned(store.size()), unsigned(store.broadcomCount()), ex.available() ? "OK" : "--");
        const size_t top = selected_ >= kVisibleNetworks ? selected_ - kVisibleNetworks + 1 : 0;
        foreground_ = TFT_WHITE;
        if (!store.size()) line(4, s.running ? "Listening for networks..." : "Scan paused; no networks");
        else if (!orderedCount_) { line(4, "No matching networks"); line(5, "F: change filter"); }
        for (size_t i = top; i < orderedCount_ && i < top + kVisibleNetworks; ++i) {
            const auto& ap = store.at(ordered_[i]); char rendered[129], name[12]; const char* ssid = ssidText(ap.info, rendered, sizeof(rendered));
            const size_t length = segmentLength(ssid, std::strlen(ssid) > 11 ? 8 : 11);
            std::snprintf(name, sizeof(name), "%.*s%s", int(length), ssid, ssid[length] ? "..." : "");
            foreground_ = classify(ap) == Classification::BroadcomSignature ? TFT_ORANGE : TFT_WHITE;
            background_ = i == selected_ ? TFT_NAVY : TFT_BLACK;
            line(3 + i - top, "%c%-8s %-11s %4d", i == selected_ ? '>' : ' ', kDetectionBadges[detectionGroup(ap)], name, ap.info.rssi);
        }
        foreground_ = TFT_CYAN; background_ = TFT_BLACK;
        if (ex.busy()) line(8, "%s", ex.message());
        else if (clearUntil_) line(8, "R again: clear live data");
        else if (int32_t(noticeUntil_ - millis()) > 0) line(8, "%s", notice_);
        else if (scannerError_[0]) line(8, "Scan error; H then D");
        else line(8, "F:%s S:%s M:CH H:help", filter, s.running ? "pause" : "run");
    }
    for (int i = 0; i < 9; ++i) {
        const auto& row = rows_[i]; auto& shown = shown_[i];
        if (!firstDraw_ && row.foreground == shown.foreground && row.background == shown.background && !std::strcmp(row.text, shown.text)) continue;
        canvas_.fillScreen(row.background);
        canvas_.setTextColor(row.foreground, row.background); canvas_.setCursor(0, 1); canvas_.print(row.text);
        canvas_.pushSprite(0, i * kRowHeight); M5Cardputer.Display.waitDMA(); shown = row;
    }
    firstDraw_ = false;
}
void DisplayUi::notify(const char* message) {
    std::snprintf(notice_, sizeof(notice_), "%s", message);
    noticeUntil_ = millis() + 5000; dirty_ = true;
}
void DisplayUi::blankScreen() {
    M5Cardputer.Display.waitDMA(); M5Cardputer.Display.setBrightness(0);
    displayOn_ = false; clearUntil_ = 0;
}
void DisplayUi::wakeScreen() {
    displayOn_ = true;
    M5Cardputer.Display.setBrightness(kBrightness[brightnessChoice_]);
    firstDraw_ = dirty_ = true;
}
void DisplayUi::scannerError(const WifiScanner& scanner) {
    seenScanErrors_ = scanner.errorCount();
    std::snprintf(scannerError_, sizeof(scannerError_), "Scan: %s", scanner.error());
    notify(scannerError_);
}
bool DisplayUi::setRunning(WifiScanner& scanner, bool running) {
    if (!scanner.setRunning(running)) { scannerError(scanner); return false; }
    scannerError_[0] = 0; return true;
}
void DisplayUi::tick(AccessPointStore& store, WifiScanner& scanner, Exporter& exporter,
                     PcapRing& ring, uint32_t& rejected, uint32_t& malformed, const char* hardware) {
    const bool exporting = exporter.busy(); exporter.tick();
    if (exporting && !exporter.busy()) {
        notify(exporter.message());
        if (resumeAfterExport_) setRunning(scanner, true);
    }
    if (scanner.errorCount() != seenScanErrors_) scannerError(scanner);
    if (clearUntil_ && int32_t(clearUntil_ - millis()) <= 0) { clearUntil_ = 0; dirty_ = true; }
    firstAllowed_ = scanner.firstChannel(); lastAllowed_ = scanner.stats().channelCount;
    updateOrder(store);
    Screen content = screen_ == Screen::Help ? helpReturn_ : screen_;
    if (content == Screen::Display) content = displayReturn_;
#if RADAR_WPS_PROBE
    if (probe_ && content == Screen::ProbeConfirm) {
        for (size_t i = 0; i < store.size(); ++i) if (!std::memcmp(store.at(i).info.bssid, probeTarget_.bssid, 6)) {
            probeTarget_ = store.at(i).info; break;
        }
    }
#else
    (void)content;
#endif
    auto& keyboard = M5Cardputer.Keyboard;
    const bool keysChanged = keyboard.isChange(), keyDown = keyboard.isPressed();
    if (!keyDown) consumeWakeKey_ = false;
    else lastInput_ = millis();
    if (!displayOn_ && keyDown && !consumeWakeKey_) {
        wakeScreen(); consumeWakeKey_ = true; clearUntil_ = 0;
    }
    if (keysChanged && keyDown && !consumeWakeKey_) {
        dirty_ = true;
        const auto& keys = keyboard.keysState();
        const bool up = keys.up || keyboard.isKeyPressed(';'), down = keys.down || keyboard.isKeyPressed('.');
        const bool left = keys.left || keyboard.isKeyPressed(','), right = keys.right || keyboard.isKeyPressed('/');
        const bool esc = keys.esc || keys.backspace || keyboard.isKeyPressed('`');
        auto pressed = [&](char letter) { for (char c : keys.word) if (c == letter || c == letter - 'a' + 'A') return true; return false; };
        const bool resetKey = pressed('r') && keys.word.size() == 1 && !up && !down && !left && !right && !esc && !keys.enter;
        const bool clearing = resetKey && screen_ == Screen::List && !exporter.busy();
        if (!clearing) clearUntil_ = 0;
        if (pressed('l')) { blankScreen(); consumeWakeKey_ = true; }
        else if (pressed('b')) {
            if (screen_ == Screen::Display) screen_ = displayReturn_;
            else if (screen_ == Screen::Help && helpReturn_ == Screen::Display) screen_ = Screen::Display;
            else { displayReturn_ = screen_ == Screen::Help ? helpReturn_ : screen_; screen_ = Screen::Display; }
        } else if (pressed('h')) {
            if (screen_ == Screen::Help) screen_ = helpReturn_;
            else { helpReturn_ = screen_; helpPage_ = screen_ == Screen::Display ? kHelpPages - 1 : 0; screen_ = Screen::Help; }
        } else if (screen_ == Screen::Help) {
            if (esc) screen_ = helpReturn_;
            else if (pressed('d')) {
                if (helpReturn_ == Screen::Display) screen_ = Screen::Display;
#if RADAR_WPS_PROBE
                else if (helpReturn_ == Screen::Probe && probe_) { screen_ = Screen::Probe; probeDetails_ = true; }
                else if (helpReturn_ != Screen::ProbeConfirm)
#else
                else
#endif
                { if (helpReturn_ != Screen::Diagnostics) diagnosticsReturn_ = helpReturn_; screen_ = Screen::Diagnostics; }
            } else if (left || up) helpPage_ = (helpPage_ + kHelpPages - 1) % kHelpPages;
            else if (right || down || keys.enter) helpPage_ = (helpPage_ + 1) % kHelpPages;
        }
#if RADAR_WPS_PROBE
        else if (probe_ && (screen_ == Screen::ProbeConfirm || screen_ == Screen::Probe)) {
            if (esc) {
                if (screen_ == Screen::Probe && probe_->busy()) probe_->cancel(scanner.stats().nowUs);
                else if (screen_ == Screen::Probe && probeDetails_) probeDetails_ = false;
                else screen_ = modalReturn_;
            } else if (screen_ == Screen::ProbeConfirm && keys.enter && !exporter.busy()) {
                if (!scanner.channelAllowed(probeTarget_.channel)) notify("Channel outside country");
                else if (probe_->request(probeTarget_)) { screen_ = Screen::Probe; probeDetails_ = false; }
            } else if (screen_ == Screen::Probe) {
                if (pressed('d') || left || right) probeDetails_ = !probeDetails_;
                if (probe_->done() && pressed('e') && !exporter.probeSaved(*probe_)) {
                    const bool running = scanner.stats().running;
                    if (!running || setRunning(scanner, false)) {
                        exporter.saveProbe(*probe_, hardware);
                        if (running) setRunning(scanner, true);
                    }
                }
            }
        }
#endif
        else if (screen_ == Screen::Indicators && indicators_) {
            if (esc) screen_ = indicatorsReturn_;
            else {
                if (up || down) indicatorField_ = 1 - indicatorField_;
                if (left || right || keys.enter) {
                    if (indicatorField_ == 0) indicators_->enableLed(!indicators_->ledEnabled());
                    else indicators_->enableSound(!indicators_->soundEnabled());
                }
            }
        }
        else if (screen_ == Screen::Display) {
            if (esc) screen_ = displayReturn_;
            else {
                if (up) displayField_ = (displayField_ + 2) % 3;
                if (down) displayField_ = (displayField_ + 1) % 3;
                if (left || right || keys.enter) {
                    if (displayField_ == 0) {
                        constexpr unsigned count = sizeof(kBrightness) / sizeof(kBrightness[0]);
                        if (left) { if (brightnessChoice_) --brightnessChoice_; }
                        else if (brightnessChoice_ + 1 < count) ++brightnessChoice_;
                        M5Cardputer.Display.setBrightness(kBrightness[brightnessChoice_]);
                    } else if (displayField_ == 1) {
                        constexpr unsigned count = sizeof(kIdleSeconds) / sizeof(kIdleSeconds[0]);
                        idleChoice_ = (idleChoice_ + (left ? count - 1 : 1)) % count;
                    } else if (keys.enter) { blankScreen(); consumeWakeKey_ = true; }
                }
            }
        } else if (screen_ == Screen::Text) {
            if (esc) screen_ = Screen::Detail;
            else if (left || up) { if (textPage_) --textPage_; }
            else if (right || down || keys.enter) ++textPage_;
        } else if (screen_ == Screen::Diagnostics) {
            if (esc) screen_ = diagnosticsReturn_;
        } else if (screen_ == Screen::Country) {
            if (esc) screen_ = modalReturn_;
            else {
                if (up || left) { countryChoice_ = (countryChoice_ + kCountryCount - 1) % kCountryCount; channelError_[0] = 0; }
                if (down || right) { countryChoice_ = (countryChoice_ + 1) % kCountryCount; channelError_[0] = 0; }
                if (keys.enter && !exporter.busy()) {
                    if (scanner.setCountry(kCountries[countryChoice_])) { scannerError_[0] = 0; screen_ = modalReturn_; }
                    else { std::snprintf(channelError_, sizeof(channelError_), "Country apply failed"); scannerError(scanner); }
                }
            }
        } else if (screen_ == Screen::Channel) {
            if (esc) screen_ = modalReturn_;
            else {
                const unsigned choices = scanner.stats().channelCount + 1;
                if (up || left) { channelChoice_ = (channelChoice_ + choices - 1) % choices; channelError_[0] = 0; }
                if (down || right) { channelChoice_ = (channelChoice_ + 1) % choices; channelError_[0] = 0; }
                if (keys.enter && !exporter.busy()) {
                    if (scanner.selectChannel(channelChoice_)) { scannerError_[0] = 0; screen_ = modalReturn_; }
                    else { std::snprintf(channelError_, sizeof(channelError_), "Apply failed: %s", scanner.error()); scannerError(scanner); }
                }
            }
        } else {
            if (esc) screen_ = Screen::List;
            else if (screen_ == Screen::Detail) {
                if (left || right || keys.enter) { page_ = (page_ + (left ? kPages - 1 : 1)) % kPages; field_ = 0; }
                else if (up || down) {
                    const unsigned fields = page_ == 0 ? 3 : page_ == 2 ? 6 : 1;
                    field_ = (field_ + (up ? fields - 1 : 1)) % fields;
                }
                if (pressed('v') && selected_ < orderedCount_) openText(store.at(ordered_[selected_]));
            } else if (screen_ == Screen::List) {
                if ((up || left) && selected_) --selected_;
                if ((down || right) && selected_ + 1 < orderedCount_) ++selected_;
                if (keys.enter && orderedCount_) { screen_ = Screen::Detail; page_ = field_ = 0; }
            }
            for (char c : keys.word) {
                if (exporter.busy() || screen_ == Screen::Text) break;
                if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
#if RADAR_WPS_PROBE
                if (c == 't' && probe_ && selected_ < orderedCount_) {
                    probeTarget_ = store.at(ordered_[selected_]).info; modalReturn_ = screen_; screen_ = Screen::ProbeConfirm; break;
                }
                if (c == 'a' && probe_ && probe_->setRandomStation(!probe_->randomStation())) notify(probe_->randomStation() ? "Test MAC: random per test" : "Test MAC: device address");
#endif
                if (c == 'f') {
                    filter_ = filter_ == Filter::All ? Filter::Wps : filter_ == Filter::Wps ? Filter::BroadcomWps : Filter::All;
                    updateOrder(store); screen_ = Screen::List;
                }
                if (c == 'n' && indicators_) { indicatorsReturn_ = screen_; screen_ = Screen::Indicators; break; }
                if (c == 'o') { signalSort_ = !signalSort_; updateOrder(store); screen_ = Screen::List; notify(signalSort_ ? "Sort: signal within groups" : "Sort: discovery order"); }
                if (c == 's') setRunning(scanner, !scanner.stats().running);
                if (c == 'r') {
                    if (!resetKey) continue;
                    if (screen_ != Screen::List) { screen_ = Screen::List; clearUntil_ = millis() + 3000; }
                    else if (!clearUntil_) clearUntil_ = millis() + 3000;
                    else {
                        clearUntil_ = 0;
                        const bool running = scanner.stats().running;
                        if (running && !setRunning(scanner, false)) continue;
                        store.clear(); ring.clear(); scanner.clear(); rejected = malformed = 0; selected_ = orderedCount_ = 0;
                        if (running) setRunning(scanner, true);
                        notify("Live data cleared; SD kept");
                    }
                }
                if (c == 'm') { modalReturn_ = screen_; channelChoice_ = scanner.stats().hopping ? 0 : scanner.stats().channel; channelError_[0] = 0; screen_ = Screen::Channel; }
                if (c == 'c') {
                    modalReturn_ = screen_; countryChoice_ = 0; channelError_[0] = 0;
                    for (size_t i = 0; i < kCountryCount; ++i) if (!std::strcmp(kCountries[i], scanner.country())) countryChoice_ = i;
                    screen_ = Screen::Country;
                }
                if (c == 'p') { ring.enable(!ring.enabled()); notify(ring.enabled() ? "PCAP buffering ON" : "PCAP buffering OFF"); }
                if (c == 'e') {
                    resumeAfterExport_ = scanner.stats().running;
                    if (resumeAfterExport_ && !setRunning(scanner, false)) continue;
                    auto stats = scanner.stats(); stats.rejected = rejected; stats.malformed = malformed; stats.storeDrops = store.dropped(); stats.storeReplacements = store.replacements();
                    const bool started = exporter.start(store, stats, ring, hardware);
                    notify(exporter.message());
                    if (!started && resumeAfterExport_) setRunning(scanner, true);
                    screen_ = Screen::List;
                }
            }
        }
    }
    const uint8_t* selected = selected_ < orderedCount_ ? store.at(ordered_[selected_]).info.bssid : nullptr;
    const uint8_t* target = nullptr;
#if RADAR_WPS_PROBE
    if (probe_ && (screen_ == Screen::ProbeConfirm || probe_->busy())) target = probeTarget_.bssid;
#endif
    store.protect(selected, target);
    bool keepVisible = exporting || exporter.busy() || screen_ == Screen::Display || screen_ == Screen::Country || screen_ == Screen::Indicators;
#if RADAR_WPS_PROBE
    keepVisible |= probe_ && (content == Screen::ProbeConfirm || probe_->busy());
#endif
    if (keepVisible) lastInput_ = millis();
    if (displayOn_ && !keepVisible && idleChoice_ && uint32_t(millis() - lastInput_) >= kIdleSeconds[idleChoice_] * 1000u) blankScreen();
    if (displayOn_ && (dirty_ || millis() - lastDraw_ >= 500)) {
        auto stats = scanner.stats(); stats.rejected = rejected; stats.malformed = malformed;
        draw(store, stats, exporter, ring); lastDraw_ = millis(); dirty_ = false;
    }
}
}
