#pragma once
#include "esp_timer.h"
#include <cstdarg>
#include <cstdio>
#include <string>
#include <vector>
constexpr int TFT_BLACK=0, TFT_WHITE=1, TFT_ORANGE=2, TFT_NAVY=3, TFT_CYAN=4;
constexpr int TFT_MAGENTA=5, TFT_DARKGREY=6, TFT_YELLOW=7;
inline uint32_t millis() { return mock::nowUs/1000; }
struct FakeDisplay {
    std::vector<std::string> lines;
    int row=0;
    bool boundsOk=true;
    unsigned directClears=0, pushes=0;
    int brightness = -1;
    bool pendingDma=false;
    std::vector<int> backgrounds = std::vector<int>(9, TFT_BLACK);
    std::vector<int> foregrounds = std::vector<int>(9, TFT_WHITE);
    void setRotation(int) {} void setTextFont(int) {} void setTextSize(int) {}
    void setTextWrap(bool) {} void setBrightness(int value) { brightness=value; } void startWrite() {} void endWrite() {}
    void fillScreen(int) { ++directClears; lines.clear(); }
    void setTextColor(int,int) {}
    void waitDMA() { pendingDma=false; }
    void setCursor(int x,int y) { row=y/11; boundsOk &= x==0 && y>=0 && y+8<=135; }
    void print(const char* text) { boundsOk &= std::string(text).size()<=40; lines.emplace_back(text); }
};
struct M5Canvas {
    FakeDisplay* display;
    std::string text;
    int background=0, foreground=1, width=0, height=0, x=0, y=0;
    float scale=1;
    inline static bool failAllocation=false;
    explicit M5Canvas(FakeDisplay* parent):display(parent) {}
    void setColorDepth(int) {} void setPsram(bool) {} void setTextFont(int) {} void setTextWrap(bool) {}
    void* createSprite(int w,int h) { width=w; height=h; return failAllocation ? nullptr : this; }
    void setTextSize(float size) { scale=size; }
    void setTextColor(int color,int) { foreground=color; }
    void fillScreen(int color) { display->boundsOk &= !display->pendingDma; background=color; text.clear(); }
    void setCursor(int cx,int cy) { x=cx; y=cy; }
    void print(const char* value) {
        text=value;
        display->boundsOk &= x>=0 && y>=0 && x+text.size()*6*scale<=width && y+8*scale<=height;
    }
    void pushSprite(int px,int py) {
        display->boundsOk &= px==0 && py>=0 && py+height<=135;
        display->lines.resize(9); display->lines.at(py/15)=text;
        display->backgrounds.at(py/15)=background; ++display->pushes;
        display->foregrounds.at(py/15)=foreground;
        display->pendingDma=true;
    }
};
struct FakeKeyboard {
    struct State {
        bool up=false,down=false,left=false,right=false,esc=false,backspace=false,enter=false;
        std::vector<char> word;
    } state;
    bool changed=false;
    bool isChange() { return changed; }
    bool isPressed() { return state.up || state.down || state.left || state.right || state.esc || state.backspace || state.enter || !state.word.empty(); }
    State& keysState() { return state; }
    bool isKeyPressed(char c) { for(auto key:state.word) if(key==c) return true; return false; }
    void event(const std::string& text) { state={};state.word.assign(text.begin(),text.end());changed=true; }
};
struct FakePower { int getBatteryLevel() { return 82; } };
struct FakeCardputer { FakeDisplay Display; FakeKeyboard Keyboard; FakePower Power; };
inline FakeCardputer M5Cardputer;

struct FakeI2c {
    bool fail=false; unsigned writes=0; uint8_t lastRegister=0,lastValue=0;
    bool writeRegister8(uint8_t,uint8_t reg,uint8_t value,uint32_t) { ++writes;lastRegister=reg;lastValue=value;return !fail; }
};
struct FakeM5 { FakeI2c In_I2C; };
inline FakeM5 M5;
