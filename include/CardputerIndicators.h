#pragma once
#include "FieldIndicators.h"
namespace radar {
class CardputerIndicators : public IndicatorHardware {
public:
    void rgb(uint8_t red, uint8_t green, uint8_t blue) override;
    bool tone() override;
    void silence() override;
private:
    bool audio_ = false;
    static constexpr size_t kSamples = 960;
    int16_t click_[kSamples * 2]{};
    static bool codec(void*, bool enabled);
};
}
