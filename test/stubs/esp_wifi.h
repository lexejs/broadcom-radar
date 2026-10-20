#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <cstring>
#if RADAR_DRIVER_COMPAT
extern "C" int ieee80211_raw_frame_sanity_check(int, const void*, int, bool);
#endif
using esp_err_t = int;
constexpr int ESP_OK = 0, ESP_ERR_INVALID_STATE = 0x103, ESP_FAIL = -1;
constexpr int ESP_ERR_INVALID_ARG = 0x102;
constexpr int ESP_ERR_WIFI_NOT_STARTED = 0x3002;
enum wifi_promiscuous_pkt_type_t { WIFI_PKT_MGMT, WIFI_PKT_DATA, WIFI_PKT_CTRL };
using wifi_promiscuous_cb_t = void (*)(void*, wifi_promiscuous_pkt_type_t);
constexpr int WIFI_STORAGE_RAM = 0, WIFI_MODE_STA = 1, WIFI_IF_STA = 0, WIFI_PS_NONE = 0, WIFI_SECOND_CHAN_NONE = 0;
constexpr unsigned WIFI_PROMIS_FILTER_MASK_MGMT = 1;
constexpr unsigned WIFI_PROMIS_FILTER_MASK_DATA = 2;
enum wifi_country_policy_t { WIFI_COUNTRY_POLICY_AUTO, WIFI_COUNTRY_POLICY_MANUAL };
struct wifi_country_t { char cc[3]; uint8_t schan, nchan; wifi_country_policy_t policy; };
struct wifi_init_config_t { int nvs_enable; int static_rx_buf_num = 0, dynamic_rx_buf_num = 0, ampdu_rx_enable = 0; };
#define WIFI_INIT_CONFIG_DEFAULT() wifi_init_config_t{1}
struct wifi_config_t { uint8_t data[64]; };
struct wifi_promiscuous_filter_t { unsigned filter_mask; };
struct wifi_pkt_rx_ctrl_t { int rx_state; uint16_t sig_len; int8_t rssi; uint8_t channel; };
struct wifi_promiscuous_pkt_t { wifi_pkt_rx_ctrl_t rx_ctrl; uint8_t payload[2400]; };
namespace mock {
inline std::vector<std::string> calls;
inline wifi_promiscuous_cb_t callback = nullptr;
inline bool enabled = false;
inline uint64_t nowUs = 1000000;
inline uint8_t channel = 0;
inline wifi_country_t country = {{'P','L',0},1,13,WIFI_COUNTRY_POLICY_MANUAL};
inline int result = ESP_OK;
inline bool failCountryOnce = false;
inline bool failMacOnce = false, radioStarted = false;
inline uint8_t stationMac[6] = {2,0,0,0,0,0xee};
inline int txResult = ESP_ERR_INVALID_ARG;
inline std::vector<std::vector<uint8_t>> transmitted;
inline int call(const char* name) { calls.emplace_back(name); return result; }
}
inline const char* esp_err_to_name(int) { return "MOCK_ERROR"; }
inline int esp_wifi_init(const wifi_init_config_t* c) { return c->nvs_enable == 0 ? mock::call("init_nvs_off") : ESP_FAIL; }
inline int esp_wifi_set_storage(int v) { return v == WIFI_STORAGE_RAM ? mock::call("storage_ram") : ESP_FAIL; }
inline int esp_wifi_set_mode(int v) { return v == WIFI_MODE_STA ? mock::call("mode_sta") : ESP_FAIL; }
inline int esp_wifi_set_config(int, const wifi_config_t* c) { for (auto b : c->data) if (b) return ESP_FAIL; return mock::call("empty_station_config"); }
inline int esp_wifi_set_country_code(const char* code, bool enabled) {
    const int result = enabled ? ESP_FAIL : mock::call("country_manual");
    if (mock::failCountryOnce) { mock::failCountryOnce=false; return ESP_FAIL; }
    if (result == ESP_OK) {
        std::memcpy(mock::country.cc, code, 2); mock::country.cc[2] = 0;
        mock::country.schan = 1;
        mock::country.nchan = !std::strcmp(code, "US") || !std::strcmp(code, "01") ? 11 : 13;
    }
    return result;
}
inline int esp_wifi_get_country(wifi_country_t* c) { *c = mock::country; return mock::call("get_country"); }
inline int esp_wifi_start() { const int result=mock::call("start_idle"); if (!result) mock::radioStarted=true; return result; }
inline int esp_wifi_set_ps(int) { return mock::call("ps_none"); }
inline int esp_wifi_set_promiscuous_filter(const wifi_promiscuous_filter_t* f) {
    if (f->filter_mask == WIFI_PROMIS_FILTER_MASK_MGMT) return mock::call("filter_mgmt_only");
#if RADAR_WPS_PROBE
    if (f->filter_mask == (WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA)) return mock::call("filter_probe_replies");
#endif
    return ESP_FAIL;
}
inline int esp_wifi_set_promiscuous_rx_cb(wifi_promiscuous_cb_t cb) { mock::callback = cb; return mock::call("register_callback"); }
inline int esp_wifi_set_promiscuous(bool enabled) { const int result=mock::call(enabled ? "capture_on" : "capture_off"); if (!result) mock::enabled=enabled; return result; }
inline int esp_wifi_set_channel(uint8_t channel, int) { const int result=mock::call("set_channel"); if (!result) mock::channel=channel; return result; }
#if RADAR_WPS_PROBE
inline int esp_wifi_get_mac(int, uint8_t* mac) {
    std::memcpy(mac,mock::stationMac,6); return mock::call("get_mac");
}
inline int esp_wifi_stop() {
    const int result=mock::call("stop_radio");
    if (result) return result;
    if (!mock::radioStarted) return ESP_ERR_WIFI_NOT_STARTED;
    mock::radioStarted=false; return ESP_OK;
}
inline int esp_wifi_set_mac(int, const uint8_t* mac) {
    const int result=mock::call("set_mac"); if (result) return result;
    if (mock::radioStarted || (mac[0]&1)) return ESP_ERR_INVALID_ARG;
    if (mock::failMacOnce) { mock::failMacOnce=false; return ESP_FAIL; }
    std::memcpy(mock::stationMac,mac,6); return ESP_OK;
}
inline int esp_wifi_80211_tx(int interface, const void* data, int length, bool sequence) {
    (void)interface;
    if (!sequence || length < 24 || length > 1500) return ESP_ERR_INVALID_ARG;
#if RADAR_DRIVER_COMPAT
    const int sanity = ieee80211_raw_frame_sanity_check(interface, data, length, sequence);
    if (sanity) return sanity;
#endif
    const auto* bytes=static_cast<const uint8_t*>(data);
    mock::transmitted.emplace_back(bytes,bytes+length); mock::call("experimental_tx"); return mock::txResult;
}
#endif
