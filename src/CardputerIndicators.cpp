#include "CardputerIndicators.h"
#include <M5Cardputer.h>
#include <esp32-hal-rgb-led.h>
#include <driver/i2s.h>
namespace radar {
void CardputerIndicators::rgb(uint8_t red, uint8_t green, uint8_t blue) {
    // GPIO38 also powers the ADV backlight. Never change it for an alert.
    neopixelWrite(21, red, green, blue);
}
bool CardputerIndicators::codec(void*, bool enabled) {
#if RADAR_ADV
    // Cardputer ADV setup from pinned M5Unified 0.2.26 (MIT).
    static const uint8_t setup[][2] = {{0x00, 0x80}, {0x01, 0xB5}, {0x02, 0x18}, {0x0D, 0x01},
                                     {0x12, 0x00}, {0x13, 0x10}, {0x32, 0xBF}, {0x37, 0x08}};
    if (!enabled) return M5.In_I2C.writeRegister8(0x18, 0x12, 0x02, 100000); // DAC power down.
    for (const auto& entry : setup)
        if (!M5.In_I2C.writeRegister8(0x18, entry[0], entry[1], 100000)) return false;
#else
    (void)enabled;
#endif
    return true;
}
bool CardputerIndicators::tone() {
    if (!audio_) {
        if (!codec(nullptr, true)) { codec(nullptr, false); return false; }
        i2s_config_t config{};
        config.mode = i2s_mode_t(I2S_MODE_MASTER | I2S_MODE_TX);
        config.sample_rate = 48000; config.bits_per_sample = I2S_BITS_PER_SAMPLE_16BIT;
        config.channel_format = I2S_CHANNEL_FMT_RIGHT_LEFT;
        config.communication_format = I2S_COMM_FORMAT_STAND_I2S;
        config.dma_buf_count = 4; config.dma_buf_len = 256; config.tx_desc_auto_clear = true;
        if (i2s_driver_install(I2S_NUM_1, &config, 0, nullptr) != ESP_OK) { codec(nullptr, false); return false; }
        audio_ = true;
        i2s_pin_config_t pins{};
        pins.mck_io_num = I2S_PIN_NO_CHANGE; pins.bck_io_num = 41; pins.ws_io_num = 43;
        pins.data_out_num = 42; pins.data_in_num = I2S_PIN_NO_CHANGE;
        if (i2s_set_pin(I2S_NUM_1, &pins) != ESP_OK) { silence(); return false; }
        // 1200 Hz, 20 ms, quiet triangle with a 1 ms fade at each end.
        for (size_t i = 0; i < kSamples; ++i) {
            const int phase = i % 40;
            int value = 80 * (phase < 10 ? phase : phase < 30 ? 20 - phase : phase - 40);
            if (i < 48) value = value * int(i) / 48;
            if (i >= kSamples - 48) value = value * int(kSamples - 1 - i) / 48;
            click_[i * 2] = click_[i * 2 + 1] = value;
        }
    }
    size_t written = 0;
    // Queue once without waiting for DMA or another task. A stalled output is an error.
    return i2s_write(I2S_NUM_1, click_, sizeof(click_), &written, 0) == ESP_OK && written == sizeof(click_);
}
void CardputerIndicators::silence() {
    if (!audio_) return;
    // No playback task to join, pending tone to drain, or retry loop on the UI thread.
    i2s_stop(I2S_NUM_1); i2s_driver_uninstall(I2S_NUM_1); codec(nullptr, false); audio_ = false;
}
}
