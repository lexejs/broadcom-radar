#include "CardputerIndicators.h"
#include <driver/i2s.h>
#include <M5Cardputer.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>
using namespace radar;
unsigned checks=0;
#define CHECK(x) do { ++checks; if(!(x))throw std::runtime_error("Audio line "+std::to_string(__LINE__)+": " #x); } while(false)
int main() {
 try {
  CardputerIndicators hardware; FieldIndicators indicators(hardware);
  ScanStats stats;stats.running=true;stats.nowUs=2000000;
  AccessPoint ap;ap.lastSeenUs=stats.nowUs;ap.info.rssi=-35;ap.info.bssid[0]=2;
  auto tick=[&](uint32_t now,size_t capacity=0) {
   audioMock::availableBytes=capacity;indicators.tick(stats,&ap,true,now);
  };
  tick(0);CHECK(!audioMock::installs && !M5.In_I2C.writes);
  indicators.enableSound(true);tick(0);tick(1); // No completed DMA buffer at startup.
  CHECK(indicators.soundEnabled() && !indicators.soundError() && audioMock::samples.empty());
  CHECK(audioMock::installs==1 && audioMock::wait==0);
  tick(2,1024);tick(3);tick(4,1024);tick(5,1792);
  CHECK(indicators.soundEnabled() && !indicators.soundError());
  CHECK(audioMock::config.tx_desc_auto_clear && audioMock::config.sample_rate==48000);
  CHECK(audioMock::pins.bck_io_num==41 && audioMock::pins.ws_io_num==43 && audioMock::pins.data_out_num==42);
  CHECK(audioMock::samples.size()==1920 && audioMock::samples.front()==0 && audioMock::samples.back()==0);
  const auto click=audioMock::samples;
  for(size_t i=0;i<click.size();i+=2) {
   CHECK(click[i]==click[i+1]);CHECK(click[i]>=-800 && click[i]<=800);
  }
  for(unsigned now=200;now<4000;now+=200) {
   tick(now);tick(now+1,3072);tick(now+2,768); // A click spans several completed buffers.
  }
  CHECK(audioMock::samples.size()==20*click.size() && audioMock::installs==1 && audioMock::wait==0);
  for(size_t i=0;i<audioMock::samples.size();i+=click.size())
   CHECK(std::equal(click.begin(),click.end(),audioMock::samples.begin()+i));
  tick(4000);tick(4001,1024); // Cancelling midway must discard the pending suffix.
  indicators.tick(stats,nullptr,true,4002);
  CHECK(!audioMock::installed && audioMock::stops==1 && audioMock::uninstalls==1);
  const auto cancelled=audioMock::samples.size();
  tick(4200);tick(4201,3840);
  CHECK(audioMock::installs==2 && audioMock::samples.size()==cancelled+click.size());
  CHECK(std::equal(click.begin(),click.end(),audioMock::samples.begin()+cancelled));
  tick(4400);tick(4401);tick(4500); // Zero writes are tolerated until the progress deadline.
  CHECK(indicators.soundEnabled());tick(4501);
  CHECK(!indicators.soundEnabled() && indicators.soundError() && !audioMock::installed);
  auto writes=audioMock::writes;tick(5000);CHECK(audioMock::writes==writes);
  indicators.enableSound(true);tick(5200);tick(5201,1024);tick(5299,1024);tick(5397,1792);
  CHECK(indicators.soundEnabled() && !indicators.soundError()); // Progress renews the deadline.
  indicators.enableSound(false);CHECK(!audioMock::installed);
  indicators.enableSound(true);tick(UINT32_MAX-20);tick(UINT32_MAX-19);tick(79);
  CHECK(indicators.soundEnabled());tick(80);
  CHECK(!indicators.soundEnabled() && indicators.soundError());
  audioMock::failInstall=true;indicators.enableSound(true);tick(5400);
  CHECK(!indicators.soundEnabled() && !audioMock::installed);
  audioMock::failInstall=false;audioMock::failPins=true;
  indicators.enableSound(true);tick(5600);
  CHECK(!indicators.soundEnabled() && !audioMock::installed);
  audioMock::failPins=false;audioMock::failWrite=true;
  indicators.enableSound(true);tick(5800);tick(5801);
  CHECK(!indicators.soundEnabled() && !audioMock::installed && audioMock::wait==0);
  audioMock::failWrite=false;M5.In_I2C.fail=true;
  auto installs=audioMock::installs;indicators.enableSound(true);tick(6000);
#if RADAR_ADV
  CHECK(!indicators.soundEnabled() && audioMock::installs==installs);
#else
  CHECK(indicators.soundEnabled() && audioMock::installs==installs+1);
#endif
  std::cout<<"PASS: "<<checks<<" audio backend assertions; empty startup DMA, partial progress, repeated clicks and faults\n";
 }catch(const std::exception& error){std::cerr<<"FAIL: "<<error.what()<<'\n';return 1;}
}
