#include "Fixtures.h"
#include "WpsProbeRadio.h"
#include "DisplayUi.h"
#include "SD.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
using namespace radar;
using namespace fixtures;
namespace {
size_t checks = 0;
void check(bool value, const char* expression, int line) {
    ++checks;
    if (!value) throw std::runtime_error(std::string("Line ")+std::to_string(line)+": "+expression);
}
#define CHECK(x) check(bool(x),#x,__LINE__)
const uint8_t station[] = {2,0,0,0,0,0xee};
Frame frame;
uint64_t nowUs = 1000000;
Observation target(const Data& bytes) {
    Observation result; CHECK(parseAdvertisement(bytes.data(),bytes.size(),-55,6,nowUs,result)); return result;
}
Frame& raw(const Data& bytes) {
    frame.length=bytes.size(); frame.channel=6; frame.timestampUs=++nowUs; frame.rssi=-55;
    std::memcpy(frame.bytes,bytes.data(),bytes.size()); return frame;
}
Data apFrame(uint8_t control, size_t body) {
    Data bytes(24+body); bytes[0]=control;
    std::memcpy(bytes.data()+4,station,6);
    const uint8_t bssid[] = {2,0,0,0,0,1};
    std::memcpy(bytes.data()+10,bssid,6); std::memcpy(bytes.data()+16,bssid,6); return bytes;
}
Data authentication() { auto bytes=apFrame(0xb0,6); bytes[26]=2; return bytes; }
Data eap(const Data& payload) {
    auto bytes=apFrame(0x08,12+payload.size()); bytes[1]=2;
    const uint8_t snap[] = {0xaa,0xaa,3,0,0,0,0x88,0x8e,1,0};
    std::memcpy(bytes.data()+24,snap,sizeof(snap)); bytes[34]=payload.size()>>8; bytes[35]=payload.size();
    std::memcpy(bytes.data()+36,payload.data(),payload.size()); return bytes;
}
Data expanded(uint8_t id, uint8_t opcode) { return eap({1,id,0,14,0xfe,0,0x37,0x2a,0,0,0,1,opcode,0}); }
Data advertisement() { auto bytes=beacon(); proprietary(bytes); Data version; tlv(version,0x104a,{0x10}); wps(bytes,version); return bytes; }
void transmit(WpsProbe& probe, int error=0) {
    CHECK(probe.pending(frame));
    CHECK(frame.length<=kProbeBytes && !std::memcmp(frame.bytes+4,probe.target().bssid,6));
    CHECK(!std::memcmp(frame.bytes+10,station,6));
    probe.transmitted(error,++nowUs);
}
void entry(WpsProbe& probe, bool submitFragment = true) {
    auto bytes=advertisement(); CHECK(probe.request(target(bytes))); probe.begin(station,nowUs);
    CHECK(!probe.pending(frame)); probe.receive(raw(bytes)); CHECK(probe.result().stage==ProbeStage::Authentication);
    CHECK(probe.pending(frame) && frame.bytes[0]==0xb0); transmit(probe);
    probe.receive(raw(authentication())); CHECK(probe.result().stage==ProbeStage::Association);
    CHECK(probe.pending(frame) && frame.bytes[0]==0 && frame.length>40); transmit(probe);
    probe.receive(raw(apFrame(0x10,6))); CHECK(probe.result().stage==ProbeStage::Identity);
    CHECK(probe.pending(frame) && frame.length==36 && frame.bytes[33]==1); transmit(probe);
    probe.receive(raw(eap({1,7,0,5,1}))); CHECK(probe.result().stage==ProbeStage::Start); transmit(probe);
    probe.receive(raw(expanded(8,1))); CHECK(probe.result().stage==ProbeStage::Differential);
    CHECK(probe.pending(frame) && frame.length==52);
    CHECK(frame.bytes[48]==4 && frame.bytes[49]==3 && frame.bytes[50]==0 && frame.bytes[51]==0);
    if (submitFragment) transmit(probe);
}
void protocolTests(const char* output) {
    WpsProbe hostapd; entry(hostapd);
    hostapd.receive(raw(expanded(9,6)));
    CHECK(hostapd.result().verdict==ProbeVerdict::HostapdLike && hostapd.result().stage==ProbeStage::Cleanup);
    CHECK(hostapd.pending(frame) && frame.bytes[0]==0xc0 && frame.bytes[24]==3); transmit(hostapd);
    CHECK(hostapd.done() && hostapd.result().cleanupAccepted && hostapd.result().driverError==0);
    CHECK(hostapd.result().txAccepted==6 && hostapd.recordCount()==12);
    CHECK(hostapd.result().response==ProbeResponse::FragmentAck && hostapd.result().differentialSent);
    CHECK(!hostapd.pending(frame)); hostapd.tick(nowUs+30000000); CHECK(!hostapd.pending(frame));
    Exporter exporter; mock::files.clear(); CHECK(exporter.saveProbe(hostapd,"Cardputer ADV"));
    for(const char* ext : {"json","pcap"}) {
        std::string key=std::string("/broadcom-radar/test-001.")+ext; CHECK(mock::files.count(key));
        if(output) {
            const auto& bytes=mock::files.at(key); std::ofstream file(std::string(output)+"/test-001."+ext,std::ios::binary);
            file.write(reinterpret_cast<const char*>(bytes.data()),bytes.size()); CHECK(bool(file));
        }
    }
    mock::files["/broadcom-radar/test-002.pcap.part"]={1,2};
    CHECK(exporter.saveProbe(hostapd,"Cardputer ADV")); CHECK(mock::files.count("/broadcom-radar/test-003.json"));
    CHECK(mock::files.at("/broadcom-radar/test-002.pcap.part")==Data({1,2}));
    Exporter failed; mock::files.clear(); mock::failWritePath="/broadcom-radar/test-001.pcap.part";
    CHECK(!failed.saveProbe(hostapd,"Cardputer ADV")); CHECK(!mock::files.count("/broadcom-radar/test-001.json"));
    mock::failWritePath.clear(); CHECK(failed.saveProbe(hostapd,"Cardputer ADV"));
    CHECK(mock::files.count("/broadcom-radar/test-002.json"));
    WpsProbe broadcom; entry(broadcom); broadcom.receive(raw(eap({4,8,0,4})));
    CHECK(broadcom.result().verdict==ProbeVerdict::BroadcomLike); transmit(broadcom,ESP_ERR_INVALID_ARG);
    CHECK(broadcom.done() && !broadcom.result().cleanupAccepted && broadcom.result().cleanupError);
    CHECK(broadcom.result().response==ProbeResponse::EapFailure);
    WpsProbe disconnected; entry(disconnected); disconnected.receive(raw(apFrame(0xc0,2)));
    CHECK(disconnected.done() && disconnected.result().verdict==ProbeVerdict::BroadcomLike);
    CHECK(disconnected.result().response==ProbeResponse::DeauthZero && !disconnected.pending(frame));
    WpsProbe otherDisconnect; entry(otherDisconnect); auto reason3=apFrame(0xc0,2); reason3[24]=3;
    otherDisconnect.receive(raw(reason3)); CHECK(otherDisconnect.result().verdict==ProbeVerdict::Unknown);
    CHECK(otherDisconnect.result().reason==ProbeReason::ApRejected && otherDisconnect.result().response==ProbeResponse::None);
    WpsProbe disassociated; entry(disassociated); disassociated.receive(raw(apFrame(0xa0,2)));
    CHECK(disassociated.result().verdict==ProbeVerdict::Unknown && disassociated.result().response==ProbeResponse::None);
    WpsProbe unsent; entry(unsent,false); unsent.receive(raw(apFrame(0xc0,2)));
    CHECK(unsent.result().verdict==ProbeVerdict::Unknown && !unsent.result().differentialSent);
    transmit(unsent,ESP_ERR_INVALID_ARG); transmit(unsent);
    CHECK(unsent.done() && unsent.result().reason==ProbeReason::DriverRejected && unsent.result().response==ProbeResponse::None);
    WpsProbe earlyDisconnect; const auto earlyAd=advertisement(); CHECK(earlyDisconnect.request(target(earlyAd)));
    earlyDisconnect.begin(station,nowUs); earlyDisconnect.receive(raw(earlyAd)); transmit(earlyDisconnect);
    earlyDisconnect.receive(raw(apFrame(0xc0,2)));
    CHECK(earlyDisconnect.done() && earlyDisconnect.result().verdict==ProbeVerdict::Unknown);
    WpsProbe repeatedStart; entry(repeatedStart); const auto accepted=repeatedStart.result().txAccepted;
    repeatedStart.receive(raw(expanded(8,1)));
    CHECK(repeatedStart.result().stage==ProbeStage::Differential && !repeatedStart.pending(frame));
    CHECK(repeatedStart.result().txAccepted==accepted);
    repeatedStart.receive(raw(expanded(9,6))); CHECK(repeatedStart.result().verdict==ProbeVerdict::HostapdLike); transmit(repeatedStart);
    WpsProbe timeout; entry(timeout); timeout.tick(nowUs+3000001);
    CHECK(timeout.result().verdict==ProbeVerdict::Unknown && timeout.result().reason==ProbeReason::Timeout); transmit(timeout);
    WpsProbe rejected; entry(rejected); rejected.receive(raw(eap({4,99,0,4})));
    CHECK(rejected.result().verdict==ProbeVerdict::Unknown && rejected.result().reason==ProbeReason::UnexpectedEap); transmit(rejected);
    WpsProbe cancelled; entry(cancelled); cancelled.cancel(nowUs);
    CHECK(cancelled.result().verdict==ProbeVerdict::Unknown && cancelled.result().reason==ProbeReason::Cancelled); transmit(cancelled);
    WpsProbe invalid; auto plain=beacon(); CHECK(!invalid.request(target(plain)));
    auto bad=target(advertisement()); bad.malformed=true; CHECK(!invalid.request(bad));
    bad.malformed=false; bad.channel=14; CHECK(!invalid.request(bad));
    bad.channel=6; bad.ssid.length=0; CHECK(!invalid.request(bad));
    WpsProbe stale; auto bytes=advertisement(); CHECK(stale.request(target(bytes))); stale.begin(station,nowUs);
    stale.receive(raw(beacon({'O','t','h','e','r'}))); CHECK(!stale.pending(frame));
    stale.tick(nowUs+10000001); CHECK(stale.done() && stale.result().verdict==ProbeVerdict::Unknown);
    WpsProbe wrong; entry(wrong); auto foreign=expanded(9,6); foreign[15]=2;
    wrong.receive(raw(foreign)); CHECK(wrong.result().stage==ProbeStage::Differential);
    foreign=expanded(9,6); foreign[9]^=1; wrong.receive(raw(foreign)); CHECK(wrong.result().stage==ProbeStage::Differential);
    auto truncated=expanded(9,6); truncated[35]=255; wrong.receive(raw(truncated)); CHECK(wrong.result().stage==ProbeStage::Differential);
    wrong.receive(raw(expanded(9,6))); CHECK(wrong.result().verdict==ProbeVerdict::HostapdLike); transmit(wrong);
    WpsProbe oldReply; entry(oldReply); auto& oldFrame=raw(eap({4,8,0,4})); oldFrame.timestampUs=nowUs-2;
    oldReply.receive(oldFrame); CHECK(oldReply.result().stage==ProbeStage::Differential && oldReply.result().verdict==ProbeVerdict::Unknown);
    oldReply.receive(raw(expanded(9,6))); CHECK(oldReply.result().verdict==ProbeVerdict::HostapdLike); transmit(oldReply);
    // Reject encrypted data, non-EAPOL payloads, MAC fragments and unrelated station traffic.
    const auto bssid=target(bytes);
    for(unsigned change=0;change<5;++change) {
        auto packet=expanded(9,6);
        if(change==0) packet[1]|=0x40;
        if(change==1) packet[31]=0;
        if(change==2) packet[22]|=1;
        if(change==3) packet[4]^=1;
        if(change==4) packet[10]^=1;
        CHECK(!isProbeReply(packet.data(),packet.size(),bssid.bssid,station));
    }
    // Exercise short and corrupt EAPOL lengths through the production parser.
    std::mt19937 random(20261019);
    WpsProbe corrupt; entry(corrupt);
    for(unsigned i=0;i<2000;++i) {
        auto packet=expanded(9,6); packet.resize(random()%80);
        for(size_t j=32;j<packet.size();++j) packet[j]=random();
        if(corrupt.busy()) corrupt.receive(raw(packet));
        CHECK(corrupt.recordCount()<=kProbeRecords);
    }
    corrupt.cancel(nowUs); if(corrupt.pending(frame)) transmit(corrupt);
    // Missing WPS on one beacon does not negate a later WPS advertisement.
    WpsProbe intermittent; CHECK(intermittent.request(target(bytes))); intermittent.begin(station,nowUs);
    intermittent.receive(raw(beacon())); CHECK(intermittent.result().stage==ProbeStage::Advertisement);
    intermittent.receive(raw(bytes)); CHECK(intermittent.result().stage==ProbeStage::Authentication);
    transmit(intermittent,ESP_ERR_INVALID_ARG); CHECK(intermittent.done() && intermittent.result().txAccepted==0);
    // A long advertisement is explicitly truncated in PCAP, without inventing an original length.
    auto longAd=bytes; for(unsigned i=0;i<5;++i) ie(longAd,255,Data(200,0));
    WpsProbe bounded; CHECK(bounded.request(target(longAd))); bounded.begin(station,nowUs); bounded.receive(raw(longAd));
    transmit(bounded,ESP_ERR_INVALID_ARG); CHECK(bounded.recordCount()==1);
    CHECK(bounded.record(0).captured==kProbeBytes && bounded.record(0).original==longAd.size());
    // Overflow cannot produce a family assessment whose response is missing from its trace.
    WpsProbe overflow; entry(overflow);
    for(unsigned i=0;i<kProbeRecords;++i) overflow.receive(raw(authentication()));
    overflow.receive(raw(expanded(9,6))); CHECK(overflow.result().verdict==ProbeVerdict::Unknown);
    CHECK(overflow.result().reason==ProbeReason::TraceFull && overflow.result().traceDropped); transmit(overflow);
    // Timeout after an accepted authentication request still attempts session cleanup.
    WpsProbe authTimeout; CHECK(authTimeout.request(target(bytes))); authTimeout.begin(station,nowUs);
    authTimeout.receive(raw(bytes)); transmit(authTimeout); authTimeout.tick(nowUs+3000001);
    CHECK(authTimeout.result().stage==ProbeStage::Cleanup && authTimeout.result().verdict==ProbeVerdict::Unknown); transmit(authTimeout);
}
void deliver(const Data& bytes, int type=WIFI_PKT_MGMT) {
    wifi_promiscuous_pkt_t packet{}; packet.rx_ctrl={0,uint16_t(bytes.size()+4),-55,mock::channel};
    std::memcpy(packet.payload,bytes.data(),bytes.size()); mock::callback(&packet,wifi_promiscuous_pkt_type_t(type));
}
void transportTests() {
    mock::sdPresent=true; mock::result=ESP_OK; mock::txResult=ESP_ERR_INVALID_ARG;
    for(bool running : {false,true}) {
        WifiScanner scanner; CHECK(scanner.begin()); CHECK(scanner.selectChannel(running?0:11));
        CHECK(scanner.setRunning(running)); const auto previous=scanner.stats();
        WpsProbe probe; WpsProbeRadio radio; Exporter exporter; auto bytes=advertisement();
        CHECK(probe.request(target(bytes))); CHECK(!radio.tick(probe,scanner,exporter,frame,"Cardputer ADV"));
        CHECK(scanner.stats().running && !scanner.stats().hopping && mock::channel==6);
        // The callback admits only frames from the pinned AP, and no general data traffic.
        auto foreign=bytes; foreign[15]=foreign[21]=2; deliver(foreign); CHECK(!scanner.pop(frame));
        deliver(bytes); CHECK(scanner.pop(frame)); probe.receive(frame);
        const auto before=mock::transmitted.size();
        const bool complete = radio.tick(probe,scanner,exporter,frame,"Cardputer ADV");
        if (running) {
            CHECK(!complete && probe.restoring()); deliver(bytes); CHECK(scanner.pop(frame)); probe.receive(frame);
            CHECK(radio.tick(probe,scanner,exporter,frame,"Cardputer ADV"));
            CHECK(probe.result().scanRxFrames == 1);
        } else CHECK(complete);
        CHECK(probe.done() && probe.result().reported && probe.result().restored);
        CHECK(probe.result().verdict==ProbeVerdict::Unknown && probe.result().reason==ProbeReason::DriverRejected);
        CHECK(probe.result().stoppedAt==ProbeStage::Authentication && probe.result().txAccepted==0);
        CHECK(probe.recordCount()==1 && mock::transmitted.size()==before+1);
        CHECK(scanner.stats().running==previous.running && scanner.stats().hopping==previous.hopping);
        CHECK(mock::channel==(previous.hopping?1:11));
        CHECK(!radio.tick(probe,scanner,exporter,frame,"Cardputer ADV"));
        CHECK(mock::transmitted.size()==before+1);
        // Original management-only capture is restored after the diagnostic.
        const auto count=scanner.stats().received; deliver(expanded(9,6),WIFI_PKT_DATA);
        CHECK(scanner.stats().received==count);
    }
    WifiScanner scanner; CHECK(scanner.begin());
    WpsProbe probe; WpsProbeRadio radio; Exporter exporter; auto bytes=advertisement();
    CHECK(probe.request(target(bytes))); radio.tick(probe,scanner,exporter,frame,"Cardputer ADV");
    probe.cancel(mock::nowUs); CHECK(!radio.tick(probe,scanner,exporter,frame,"Cardputer ADV"));
    CHECK(probe.restoring()); mock::nowUs += 1500001;
    CHECK(radio.tick(probe,scanner,exporter,frame,"Cardputer ADV"));
    CHECK(probe.result().scanRxFrames == 0);
    CHECK(probe.result().restored && scanner.stats().running && scanner.stats().hopping);
    CHECK(probe.request(target(bytes))); radio.tick(probe,scanner,exporter,frame,"Cardputer ADV");
    probe.cancel(mock::nowUs); mock::result=ESP_FAIL;
    CHECK(radio.tick(probe,scanner,exporter,frame,"Cardputer ADV")); CHECK(!probe.result().restored);
    mock::result=ESP_OK;
}
void stationIdentityTests() {
    for (unsigned failure=0;failure<3;++failure) {
        WifiScanner scanner; CHECK(scanner.begin()); CHECK(scanner.selectChannel(11)); CHECK(scanner.setRunning(false));
        WpsProbe probe; CHECK(probe.setRandomStation(true)); WpsProbeRadio radio; Exporter exporter;
        const auto bytes=advertisement(); const auto before=mock::transmitted.size();
        CHECK(probe.request(target(bytes)) && !probe.setRandomStation(false));
        if (failure==1) mock::failMacOnce=true;
        radio.tick(probe,scanner,exporter,frame,"Cardputer ADV");
        if (failure!=1) {
            CHECK(probe.result().stationRandomized && (probe.station()[0]&3)==2);
            CHECK(std::memcmp(probe.station(),station,6)!=0 && !std::memcmp(probe.station(),mock::stationMac,6));
            if (failure==2) mock::failMacOnce=true;
            probe.cancel(mock::nowUs); CHECK(radio.tick(probe,scanner,exporter,frame,"Cardputer ADV"));
        }
        CHECK(probe.done() && probe.result().stationRotationRequested && !scanner.stats().running);
        CHECK(mock::transmitted.size()==before);
        if (failure==2) {
            CHECK(!probe.result().restored && probe.result().stationRestoreError==ESP_FAIL);
            std::memcpy(mock::stationMac,station,6); // Restore the test fixture after the simulated device failure.
        } else {
            CHECK(probe.result().restored && !probe.result().stationRestoreError && !std::memcmp(mock::stationMac,station,6));
            CHECK(scanner.stats().channel==11 && !scanner.stats().hopping);
        }
    }
}
void uiTests() {
    WifiScanner scanner; CHECK(scanner.begin()); AccessPointStore store; store.observe(target(advertisement()));
    WpsProbe probe; Exporter exporter; PcapRing ring; DisplayUi ui; CHECK(ui.begin()); ui.attachProbe(probe);
    uint32_t rejected=0,malformed=0;
    auto tick=[&]() { mock::nowUs+=500000; ui.tick(store,scanner,exporter,ring,rejected,malformed,"Cardputer ADV"); M5Cardputer.Keyboard.changed=false; };
    auto key=[&](const char* text) { M5Cardputer.Keyboard.event(text); tick(); };
    key("f"); CHECK(M5Cardputer.Display.lines[8].find("F:WPS")!=std::string::npos);
    key("t"); CHECK(!probe.busy()); CHECK(M5Cardputer.Display.lines[0]=="EXPERIMENTAL WPS TEST");
    CHECK(M5Cardputer.Display.lines[2].find("02:00:00:00:00:01")!=std::string::npos);
    key("`"); CHECK(!probe.busy()); CHECK(M5Cardputer.Display.lines[0].find("BRCM-RDR ")==0);
    key("t"); key("r"); key("f"); CHECK(store.size()==1 && !probe.busy());
    M5Cardputer.Keyboard.event(""); M5Cardputer.Keyboard.state.enter=true; tick(); CHECK(probe.requested());
    key("s"); key("f"); CHECK(scanner.stats().running); key("`"); CHECK(probe.done() && probe.result().reason==ProbeReason::Cancelled);
    key("`"); CHECK(M5Cardputer.Display.lines[8].find("F:WPS")!=std::string::npos);
    key("a"); CHECK(probe.randomStation()); key("a"); CHECK(!probe.randomStation());
    CHECK(M5Cardputer.Display.boundsOk && M5Cardputer.Display.directClears==0);
}
void blockedStartUiTests() {
    WifiScanner scanner; CHECK(scanner.begin()); AccessPointStore store;
    auto noWps=beacon({'H','K','_','O','m','n','i','_','2','0','+','_','S','e','t','u','p','_','3','a','4'});
    proprietary(noWps); store.observe(target(noWps));
    WpsProbe probe; Exporter exporter; PcapRing ring; DisplayUi ui; CHECK(ui.begin()); ui.attachProbe(probe);
    uint32_t rejected=0,malformed=0;
    auto tick=[&]() { mock::nowUs+=500000; ui.tick(store,scanner,exporter,ring,rejected,malformed,"Cardputer ADV"); M5Cardputer.Keyboard.changed=false; };
    auto key=[&](const char* text) { M5Cardputer.Keyboard.event(text); tick(); };
    auto enter=[&]() { M5Cardputer.Keyboard.event(""); M5Cardputer.Keyboard.state.enter=true; tick(); };
    const auto txBefore=mock::transmitted.size(); key("t"); enter();
    CHECK(!probe.busy());
    CHECK(M5Cardputer.Display.lines[0]=="EXPERIMENTAL WPS TEST");
    CHECK(M5Cardputer.Display.lines[4]=="WPS not observed");
    CHECK(mock::transmitted.size()==txBefore && scanner.stats().running);
    // Fresh WPS evidence arriving while confirmation is open must update the pinned AP.
    auto withWps=noWps; Data attributes; tlv(attributes,0x104a,{0x10}); wps(withWps,attributes);
    store.observe(target(withWps)); tick(); enter(); CHECK(probe.requested());
    CHECK(probe.target().ssid.length==21 && probe.target().ssid.data[10]=='+');
    key("`"); CHECK(probe.done());
    // A hidden SSID stays on the confirmation screen with its actual blocking reason.
    store.clear(); auto hidden=beacon({}); proprietary(hidden); Data version; tlv(version,0x104a,{0x10}); wps(hidden,version);
    store.observe(target(hidden)); key("`"); key("t"); enter();
    CHECK(!probe.busy() && M5Cardputer.Display.lines[4]=="Hidden SSID");
    key("`"); CHECK(M5Cardputer.Display.lines[0].find("BRCM-RDR ")==0);
}
void uiResultTests() {
    mock::files.clear(); mock::sdPresent=true; mock::result=ESP_OK;
    WifiScanner scanner; CHECK(scanner.begin()); AccessPointStore store; store.observe(target(advertisement()));
    WpsProbe probe; Exporter exporter; CHECK(exporter.mount()); PcapRing ring; DisplayUi ui; CHECK(ui.begin()); ui.attachProbe(probe);
    uint32_t rejected=0,malformed=0;
    auto tick=[&]() { mock::nowUs+=600000; ui.tick(store,scanner,exporter,ring,rejected,malformed,"Cardputer ADV"); M5Cardputer.Keyboard.changed=false; };
    auto key=[&](const char* text) { M5Cardputer.Keyboard.event(text); tick(); };
    auto enter=[&]() { M5Cardputer.Keyboard.event(""); M5Cardputer.Keyboard.state.enter=true; tick(); };
    auto secondary=[&]() {
        CHECK(M5Cardputer.Display.lines[8].find("Esc:")==std::string::npos);
        CHECK(M5Cardputer.Display.lines[8].find("E:")==std::string::npos);
        CHECK(M5Cardputer.Display.lines[8].find("Enter:")==std::string::npos);
        CHECK(M5Cardputer.Display.boundsOk);
    };
    enter(); key("/"); key("/"); key("t"); secondary();
    key("h"); key("s"); CHECK(scanner.stats().running); key("`");
    CHECK(M5Cardputer.Display.lines[0]=="EXPERIMENTAL WPS TEST");
    key("`"); CHECK(M5Cardputer.Display.lines[0]=="3/7 IDENTITY");
    key("t"); enter(); CHECK(probe.requested());
    probe.begin(station,mock::nowUs); tick();
    CHECK(M5Cardputer.Display.lines[3]=="Checking fresh AP data"); secondary();
    key("h"); key("s"); key("f"); CHECK(probe.busy() && scanner.stats().running);
    // A test completes while Help is open; closing Help returns to its current result.
    probe.cancel(mock::nowUs); probe.startRestoration(true,true,mock::nowUs); probe.completeReport(true);
    CHECK(exporter.saveProbe(probe,"Cardputer ADV"));
    key("h"); CHECK(M5Cardputer.Display.lines[3]=="TEST CANCELLED"); secondary();
    CHECK(M5Cardputer.Display.lines[6]=="Scan: resumed; RX unseen");
    const auto fileCount=mock::files.size(); key("e"); CHECK(mock::files.size()==fileCount);
    key("d"); CHECK(M5Cardputer.Display.lines[0]=="TEST DIAGNOSTICS"); secondary();
    key("`"); CHECK(M5Cardputer.Display.lines[0]=="WPS TEST RESULT");
    // A successful explicit reply remains an uncalibrated candidate, with its own report.
    entry(probe); probe.receive(raw(expanded(9,6))); transmit(probe);
    probe.startRestoration(true,true,mock::nowUs); probe.completeReport(true); CHECK(exporter.saveProbe(probe,"Cardputer ADV")); tick();
    CHECK(M5Cardputer.Display.lines[3]=="Candidate: hostapd-like");
    CHECK(M5Cardputer.Display.lines[4]=="Reply: WPS fragment ACK");
    CHECK(M5Cardputer.Display.lines[5]=="Uncalibrated; not proof");
    CHECK(M5Cardputer.Display.lines[8]=="JSON + PCAP saved");
    const auto report=M5Cardputer.Display.lines[7];
    auto stats=scanner.stats(); const auto& ap=store.at(0); const auto bytes=advertisement();
    CHECK(exporter.saveDetection(ap.info,&ap,raw(bytes),stats,"Cardputer ADV")); tick();
    CHECK(std::string(exporter.message()).find("brcm-")!=std::string::npos);
    CHECK(M5Cardputer.Display.lines[7]==report);
    probe.startRestoration(true,true,mock::nowUs); nowUs=mock::nowUs;
    probe.receive(raw(advertisement())); probe.completeReport(true); tick();
    CHECK(M5Cardputer.Display.lines[6]=="Scan: resumed; RX seen");
    probe.startRestoration(true,false,mock::nowUs); probe.completeReport(true); tick();
    CHECK(M5Cardputer.Display.lines[6]=="Scan: restored paused");
    // Attempts cancelled before begin both have startedUs=0 but cannot share report state.
    CHECK(probe.request(target(advertisement()))); const auto attempt=probe.attemptId(); probe.cancel(mock::nowUs); probe.completeReport(false);
    CHECK(probe.result().startedUs==0 && !exporter.probeSaved(probe));
    mock::failWrite=true; CHECK(!exporter.saveProbe(probe,"Cardputer ADV")); tick();
    CHECK(M5Cardputer.Display.lines[6]=="Scan: restore FAILED");
    CHECK(M5Cardputer.Display.lines[7].find("Test save failed")==0);
    CHECK(M5Cardputer.Display.lines[8]=="Report not saved yet");
    mock::failWrite=false; key("e"); CHECK(exporter.probeSaved(probe));
    CHECK(M5Cardputer.Display.lines[6]=="Scan: restore FAILED");
    CHECK(M5Cardputer.Display.lines[8]=="JSON + PCAP saved");
    const auto savedCount=mock::files.size(); key("e"); CHECK(mock::files.size()==savedCount);
    CHECK(probe.request(target(advertisement()))); probe.cancel(mock::nowUs); probe.completeReport(true);
    CHECK(probe.attemptId()!=attempt && probe.result().startedUs==0);
    CHECK(!exporter.probeSaved(probe)); CHECK(std::string(exporter.probeMessage(probe))=="Report: pending");
    // Esc closes Help first, then cancels the still-running test.
    CHECK(probe.request(target(advertisement()))); probe.begin(station,mock::nowUs);
    key("h"); key("`"); CHECK(probe.busy()); key("`"); CHECK(probe.done());
    key("`"); CHECK(M5Cardputer.Display.lines[0]=="3/7 IDENTITY");
    // Unavailable targets show their real reason, with no misleading promise to wait.
    key("`"); store.clear(); auto invalid=target(advertisement()); invalid.channel=14; store.observe(invalid);
    key("t"); CHECK(M5Cardputer.Display.lines[4]=="Unsupported channel");
    CHECK(M5Cardputer.Display.lines[5]=="Check country settings"); secondary();
    key("`"); store.clear(); auto outside=target(advertisement()); outside.channel=13; store.observe(outside);
    CHECK(scanner.setCountry("US")); key("t");
    CHECK(M5Cardputer.Display.lines[4]=="Channel outside country"); enter(); CHECK(!probe.busy());
    CHECK(scanner.setCountry("PL"));
    key("`"); store.clear(); auto hidden=beacon({}); proprietary(hidden); store.observe(target(hidden));
    CHECK(scanner.setRunning(false)); key("t");
    CHECK(M5Cardputer.Display.lines[1]=="<hidden>");
    CHECK(M5Cardputer.Display.lines[5]=="Capture paused; return");
    CHECK(M5Cardputer.Display.lines[6]=="No packets sent"); secondary();
}
void uiDisplayWakeTests() {
    WifiScanner scanner; CHECK(scanner.begin()); AccessPointStore store; store.observe(target(advertisement()));
    WpsProbe probe; Exporter exporter; PcapRing ring; DisplayUi ui; CHECK(ui.begin()); ui.attachProbe(probe);
    uint32_t rejected=0,malformed=0;
    auto tick=[&](uint64_t elapsed=1000) { mock::nowUs+=elapsed; ui.tick(store,scanner,exporter,ring,rejected,malformed,"Cardputer ADV"); M5Cardputer.Keyboard.changed=false; };
    auto release=[&]() { M5Cardputer.Keyboard.event(""); tick(); };
    auto key=[&](const char* value) { M5Cardputer.Keyboard.event(value); tick(); release(); };
    auto enter=[&]() { M5Cardputer.Keyboard.event(""); M5Cardputer.Keyboard.state.enter=true; tick(); release(); };
    release(); key("b"); key("."); key("/"); key("`"); // Optional 30-second timer.
    key("t"); tick(31000000); CHECK(M5Cardputer.Display.brightness==100 && !probe.busy());
    key("b"); key("h"); key("h"); key("b");
    CHECK(M5Cardputer.Display.lines[0]=="EXPERIMENTAL WPS TEST");
    const auto transmissions=mock::transmitted.size();
    key("l"); enter(); CHECK(M5Cardputer.Display.brightness==100 && !probe.busy());
    CHECK(mock::transmitted.size()==transmissions); enter(); CHECK(probe.requested());
    key("b"); tick(31000000); key("b");
    CHECK(probe.requested() && M5Cardputer.Display.brightness==100);
    key("l"); key("`"); CHECK(probe.busy()); // Wake Escape cannot cancel the running test.
    key("`"); CHECK(probe.done() && probe.result().reason==ProbeReason::Cancelled);
    CHECK(M5Cardputer.Display.brightness==100); tick(31000000); CHECK(M5Cardputer.Display.brightness==0);
    key("e"); CHECK(!exporter.probeSaved(probe)); // Wake E cannot write another report.
    CHECK(M5Cardputer.Display.brightness==100 && M5Cardputer.Display.boundsOk);
}
}
int main(int argc, char** argv) {
    try {
        protocolTests(argc>1?argv[1]:nullptr); transportTests(); stationIdentityTests(); uiTests(); blockedStartUiTests(); uiResultTests(); uiDisplayWakeTests();
        std::cout<<"PASS: "<<checks<<" experimental WPS checks; simulated responses only, not RF calibration\n";
    } catch(const std::exception& e) { std::cerr<<"FAIL: "<<e.what()<<'\n'; return 1; }
}
