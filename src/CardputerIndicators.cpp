#include "CardputerIndicators.h"
#include <M5Cardputer.h>
#include <esp32-hal-rgb-led.h>
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
    auto& speaker = M5Cardputer.Speaker;
    if (!audio_) {
        auto config = speaker.config();
        config.pin_bck = 41; config.pin_ws = 43; config.pin_data_out = 42;
        config.i2s_port = I2S_NUM_1; config.magnification = 16;
        config.stereo = false;
        speaker.config(config); speaker.setVolume(32);
        if (!codec(nullptr, true)) { codec(nullptr, false); return false; }
        if (!speaker.begin()) { speaker.end(); codec(nullptr, false); return false; }
        audio_ = true;
    }
    return speaker.tone(1200, 20);
}
void CardputerIndicators::silence() {
    if (!audio_) return;
    M5Cardputer.Speaker.stop(); M5Cardputer.Speaker.end(); codec(nullptr, false); audio_ = false;
}
}
