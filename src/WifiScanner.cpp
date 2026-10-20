#include "WifiScanner.h"
#include "Parsers.h"
#if RADAR_WPS_PROBE
#include "WpsProbe.h"
#endif
#include <esp_event.h>
#include <esp_netif.h>
#include <esp_timer.h>
#include <cstring>
namespace radar {
WifiScanner* WifiScanner::instance_ = nullptr;
bool WifiScanner::check(esp_err_t err) {
    if (err == ESP_OK) return true;
    error_ = esp_err_to_name(err);
    ++errorCount_;
    return false;
}
bool WifiScanner::begin() {
    queue_ = xQueueCreateStatic(kQueueDepth, sizeof(Frame), queueStorage_, &queueControl_);
    if (!queue_) { error_ = "Frame queue unavailable"; return false; }
    if (!check(esp_netif_init())) return false;
    auto eventResult = esp_event_loop_create_default();
    if (eventResult != ESP_OK && eventResult != ESP_ERR_INVALID_STATE) return check(eventResult);
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    init.nvs_enable = 0; // Never load another firmware's credentials.
    init.static_rx_buf_num = 4;
    init.dynamic_rx_buf_num = 8;
    init.ampdu_rx_enable = 0; // Advertisements are not aggregated data frames.
    if (!check(esp_wifi_init(&init)) || !check(esp_wifi_set_storage(WIFI_STORAGE_RAM)) ||
        !check(esp_wifi_set_mode(WIFI_MODE_STA))) return false;
    wifi_config_t station{};
    if (!check(esp_wifi_set_config(WIFI_IF_STA, &station)) ||
        !check(esp_wifi_set_country_code(RADAR_COUNTRY, false))) return false;
    wifi_country_t country{};
    if (!check(esp_wifi_get_country(&country))) return false;
    if (country.policy != WIFI_COUNTRY_POLICY_MANUAL || !country.nchan || !country.schan || country.schan > 13) {
        error_ = "Unsupported regulatory policy"; return false;
    }
    firstChannel_ = channel_ = country.schan;
    std::memcpy(country_, country.cc, 2); country_[2] = 0;
    unsigned last = country.schan + country.nchan - 1;
    lastChannel_ = last > 13 ? 13 : last;
    // Starting an idle STA creates its control block. It does not connect or scan.
    // No Arduino WiFi layer, network interface, IP stack handlers or auto-reconnect.
    if (!check(esp_wifi_start()) || !check(esp_wifi_set_ps(WIFI_PS_NONE))) return false;
    wifi_promiscuous_filter_t filter{};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    instance_ = this;
    if (!check(esp_wifi_set_promiscuous_filter(&filter)) ||
        !check(esp_wifi_set_promiscuous_rx_cb(receive)) ||
        !check(esp_wifi_set_channel(channel_, WIFI_SECOND_CHAN_NONE))) return false;
    ready_ = true;
    startedUs_ = esp_timer_get_time();
    return setRunning(true);
}
void WifiScanner::receive(void* buffer, wifi_promiscuous_pkt_type_t type) {
    auto* self = instance_;
    if (!self || !buffer) return;
    const auto* packet = static_cast<const wifi_promiscuous_pkt_t*>(buffer);
    const auto& rx = packet->rx_ctrl;
    // IDF 4.4.7 sig_len includes the four FCS bytes; raw PCAP omits them.
    if (rx.rx_state != 0 || rx.sig_len < 28) return;
#if RADAR_WPS_PROBE
    if (self->probeCapture_) {
        if ((type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) ||
            !isProbeReply(packet->payload, rx.sig_len - 4, self->probeBssid_, self->probeStation_)) return;
    } else
#endif
    if (type != WIFI_PKT_MGMT || rx.sig_len < 40 || !isAdvertisement(packet->payload, rx.sig_len - 4)) return;
    self->received_.fetch_add(1, std::memory_order_relaxed);
    const size_t length = rx.sig_len - 4;
    if (length > kMaxFrame) { self->oversize_.fetch_add(1, std::memory_order_relaxed); return; }
    auto& frame = self->scratch_;
    frame.length = length; frame.rssi = rx.rssi; frame.channel = rx.channel;
    frame.timestampUs = esp_timer_get_time();
    std::memcpy(frame.bytes, packet->payload, length);
    if (xQueueSend(self->queue_, &frame, 0) != pdTRUE) self->drops_.fetch_add(1, std::memory_order_relaxed);
}
#if RADAR_WPS_PROBE
bool WifiScanner::probeCapture(bool enabled, const uint8_t* bssid, const uint8_t* station) {
    if (running_) return false;
    wifi_promiscuous_filter_t filter{};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | (enabled ? WIFI_PROMIS_FILTER_MASK_DATA : 0);
    if (!check(esp_wifi_set_promiscuous_filter(&filter))) return false;
    if (enabled) { std::memcpy(probeBssid_, bssid, 6); std::memcpy(probeStation_, station, 6); }
    probeCapture_ = enabled; return true;
}
#endif
bool WifiScanner::setRunning(bool run) {
    if (!ready_) return false;
    if (!check(esp_wifi_set_promiscuous(run))) return false;
    running_ = run;
    if (run) {
        listened_ |= 1 << (channel_ - 1);
        nextHopUs_ = esp_timer_get_time() + kDwellMs * 1000ULL;
    } else {
        // Callback has finished when promiscuous disable returns; queued copies are ours.
        discarded_ += uxQueueMessagesWaiting(queue_);
        xQueueReset(queue_);
    }
    return true;
}
bool WifiScanner::selectChannel(uint8_t channel) {
    if (!ready_ || (channel && (channel < firstChannel_ || channel > lastChannel_))) return false;
    const uint8_t selected = channel ? channel : firstChannel_;
    if (!check(esp_wifi_set_channel(selected, WIFI_SECOND_CHAN_NONE))) return false;
    channel_ = selected; hopping_ = !channel;
    if (running_) listened_ |= 1 << (channel_ - 1);
    nextHopUs_ = esp_timer_get_time() + kDwellMs * 1000ULL;
    return true;
}
bool WifiScanner::setCountry(const char* code) {
    if (!ready_ || !code) return false;
    bool supported = false;
    for (const auto* known : kCountries) if (!std::strcmp(known, code)) supported = true;
    if (!supported) { error_ = "Unsupported country"; ++errorCount_; return false; }
    if (!std::strcmp(country_, code)) return true;
    const bool wasRunning = running_;
    if (wasRunning && !setRunning(false)) return false;
    char previous[3]; std::memcpy(previous, country_, sizeof(previous));
    const uint8_t previousChannel = channel_, previousFirst = firstChannel_, previousLast = lastChannel_;
    auto restore = [&]() {
        const bool restoredCountry = check(esp_wifi_set_country_code(previous, false));
        const bool restoredChannel = check(esp_wifi_set_channel(previousChannel, WIFI_SECOND_CHAN_NONE));
        channel_ = previousChannel; firstChannel_ = previousFirst; lastChannel_ = previousLast;
        std::memcpy(country_, previous, sizeof(country_));
        if (restoredCountry && restoredChannel && wasRunning) setRunning(true);
        return false;
    };
    wifi_country_t chosen{};
    bool applied = check(esp_wifi_set_country_code(code, false)) && check(esp_wifi_get_country(&chosen));
    if (applied && (chosen.policy != WIFI_COUNTRY_POLICY_MANUAL || !chosen.schan || !chosen.nchan || chosen.schan > 13 || std::memcmp(chosen.cc, code, 2))) {
        error_ = "Unsupported regulatory policy"; ++errorCount_; applied = false;
    }
    const unsigned last = chosen.schan + chosen.nchan - 1;
    const uint8_t upper = last > 13 ? 13 : last;
    const uint8_t selected = channel_ >= chosen.schan && channel_ <= upper ? channel_ : chosen.schan;
    if (applied) applied = check(esp_wifi_set_channel(selected, WIFI_SECOND_CHAN_NONE));
    if (!applied) return restore();
    firstChannel_ = chosen.schan; lastChannel_ = upper; channel_ = selected;
    std::memcpy(country_, code, sizeof(country_));
    if (wasRunning && !setRunning(true)) return restore();
    return true;
}
void WifiScanner::tick() {
    if (!ready_ || !running_ || !hopping_ || uint64_t(esp_timer_get_time()) < nextHopUs_) return;
    const uint8_t next = channel_ < lastChannel_ ? channel_ + 1 : firstChannel_;
    if (!check(esp_wifi_set_channel(next, WIFI_SECOND_CHAN_NONE))) { setRunning(false); return; }
    channel_ = next; listened_ |= 1 << (channel_ - 1);
    nextHopUs_ = esp_timer_get_time() + kDwellMs * 1000ULL;
}
void WifiScanner::clear() {
    if (running_) return;
    xQueueReset(queue_);
    received_ = drops_ = oversize_ = 0;
    discarded_ = 0; listened_ = 0; startedUs_ = esp_timer_get_time();
}
ScanStats WifiScanner::stats() const {
    ScanStats stats;
    std::memcpy(stats.country, country_, sizeof(stats.country));
    stats.startedUs = startedUs_; stats.nowUs = esp_timer_get_time();
    stats.received = received_.load(std::memory_order_relaxed);
    stats.queueDrops = drops_.load(std::memory_order_relaxed);
    stats.oversizeDrops = oversize_.load(std::memory_order_relaxed);
    stats.discardedOnPause = discarded_;
    stats.listenedChannels = listened_; stats.channel = channel_; stats.channelCount = lastChannel_;
    stats.running = running_; stats.hopping = hopping_;
    return stats;
}
}
