#pragma once
#include "esp_wifi.h"
#include <cstddef>
#include <cstdint>
#include <vector>
constexpr int I2S_NUM_1=1, I2S_MODE_MASTER=1, I2S_MODE_TX=2;
constexpr int I2S_BITS_PER_SAMPLE_16BIT=16, I2S_CHANNEL_FMT_RIGHT_LEFT=0;
constexpr int I2S_COMM_FORMAT_STAND_I2S=1, I2S_PIN_NO_CHANGE=-1;
using i2s_mode_t=int;
struct i2s_config_t { int mode=0,sample_rate=0,bits_per_sample=0,channel_format=0,communication_format=0,dma_buf_count=0,dma_buf_len=0; bool tx_desc_auto_clear=false; };
struct i2s_pin_config_t { int mck_io_num=-1,bck_io_num=-1,ws_io_num=-1,data_out_num=-1,data_in_num=-1; };
namespace audioMock {
inline bool installed=false,failInstall=false,failPins=false,failWrite=false;
inline size_t availableBytes=0;
inline unsigned installs=0,stops=0,uninstalls=0,writes=0,wait=0;
inline i2s_config_t config;
inline i2s_pin_config_t pins;
inline std::vector<int16_t> samples;
}
inline int i2s_driver_install(int, const i2s_config_t* config, int, void*) {
 ++audioMock::installs; audioMock::config=*config;
 if(audioMock::failInstall)return ESP_FAIL;
 audioMock::installed=true;audioMock::availableBytes=0;return ESP_OK;
}
inline int i2s_set_pin(int,const i2s_pin_config_t* pins) { audioMock::pins=*pins;return audioMock::failPins?ESP_FAIL:ESP_OK; }
inline int i2s_write(int,const void* bytes,size_t size,size_t* written,unsigned wait) {
 ++audioMock::writes;audioMock::wait=wait;
 *written=audioMock::failWrite?0:size;
 if (*written>audioMock::availableBytes) *written=audioMock::availableBytes;
 audioMock::availableBytes-=*written;
 const auto* samples=static_cast<const int16_t*>(bytes);
 audioMock::samples.insert(audioMock::samples.end(),samples,samples+*written/2);
 return audioMock::failWrite?ESP_FAIL:ESP_OK;
}
inline int i2s_stop(int) {++audioMock::stops;return ESP_OK;}
inline int i2s_driver_uninstall(int) {++audioMock::uninstalls;audioMock::installed=false;return ESP_OK;}
