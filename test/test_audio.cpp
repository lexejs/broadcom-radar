#include "CardputerIndicators.h"
#include <driver/i2s.h>
#include <M5Cardputer.h>
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
  indicators.tick(stats,&ap,true,0);CHECK(!audioMock::installs && !M5.In_I2C.writes);
  indicators.enableSound(true);
  for(unsigned now=0;now<4000;now+=200)indicators.tick(stats,&ap,true,now);
  CHECK(audioMock::writes==20 && audioMock::installs==1 && audioMock::wait==0);
  CHECK(audioMock::config.tx_desc_auto_clear && audioMock::config.sample_rate==48000);
  CHECK(audioMock::pins.bck_io_num==41 && audioMock::pins.ws_io_num==43 && audioMock::pins.data_out_num==42);
  CHECK(audioMock::samples.size()==1920 && audioMock::samples.front()==0 && audioMock::samples.back()==0);
  for(size_t i=0;i<audioMock::samples.size();i+=2) {
   CHECK(audioMock::samples[i]==audioMock::samples[i+1]);CHECK(audioMock::samples[i]>=-800 && audioMock::samples[i]<=800);
  }
  indicators.tick(stats,nullptr,true,4000); // Same suspension used for test confirmation.
  CHECK(!audioMock::installed && audioMock::stops==1 && audioMock::uninstalls==1);
  indicators.tick(stats,&ap,true,4200);CHECK(audioMock::writes==21 && audioMock::installs==2);
  audioMock::shortWrite=true;indicators.tick(stats,&ap,true,4400);
  CHECK(!indicators.soundEnabled() && indicators.soundError() && !audioMock::installed);
  auto writes=audioMock::writes;indicators.tick(stats,&ap,true,5000);CHECK(audioMock::writes==writes);
  audioMock::shortWrite=false;audioMock::failInstall=true;
  indicators.enableSound(true);indicators.tick(stats,&ap,true,5200);
  CHECK(!indicators.soundEnabled() && !audioMock::installed);
  audioMock::failInstall=false;audioMock::failPins=true;
  indicators.enableSound(true);indicators.tick(stats,&ap,true,5400);
  CHECK(!indicators.soundEnabled() && !audioMock::installed);
  audioMock::failPins=false;audioMock::failWrite=true;
  indicators.enableSound(true);indicators.tick(stats,&ap,true,5600);
  CHECK(!indicators.soundEnabled() && !audioMock::installed && audioMock::wait==0);
  audioMock::failWrite=false;M5.In_I2C.fail=true;
  auto installs=audioMock::installs;indicators.enableSound(true);indicators.tick(stats,&ap,true,5800);
#if RADAR_ADV
  CHECK(!indicators.soundEnabled() && audioMock::installs==installs);
#else
  CHECK(indicators.soundEnabled() && audioMock::installs==installs+1);
#endif
  std::cout<<"PASS: "<<checks<<" audio backend assertions; repeated clicks, DMA faults and test suspension\n";
 }catch(const std::exception& error){std::cerr<<"FAIL: "<<error.what()<<'\n';return 1;}
}
