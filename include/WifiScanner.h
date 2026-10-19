#pragma once
#include "RadarTypes.h"
#include <atomic>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
namespace radar {
class WifiScanner {
public:
    bool begin();
    bool setRunning(bool running);
    bool selectChannel(uint8_t channel); // Zero selects hopping.
    void tick();
    bool pop(Frame& frame) { return xQueueReceive(queue_, &frame, 0) == pdTRUE; }
    void clear(); // Call with capture paused.
    ScanStats stats() const;
    const char* error() const { return error_; }
private:
    static void receive(void* buffer, wifi_promiscuous_pkt_type_t type);
    bool check(esp_err_t error);
    static WifiScanner* instance_;
    StaticQueue_t queueControl_{};
    alignas(4) uint8_t queueStorage_[kQueueDepth * sizeof(Frame)]{};
    QueueHandle_t queue_ = nullptr;
    Frame scratch_; // Only accessed by the serialized Wi-Fi task callback.
    std::atomic<uint32_t> received_{0}, drops_{0}, oversize_{0};
    uint32_t discarded_ = 0;
    uint64_t startedUs_ = 0, nextHopUs_ = 0;
    uint16_t listened_ = 0;
    uint8_t channel_ = 1, firstChannel_ = 1, lastChannel_ = 13;
    bool ready_ = false, running_ = false, hopping_ = true;
    const char* error_ = "";
};
}
