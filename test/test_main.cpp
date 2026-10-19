#include "Fixtures.h"
#include "Export.h"
#include "WifiScanner.h"
#include "SD.h"
#include "DisplayUi.h"
#include "M5Cardputer.h"
#include <array>
#include <cstdlib>
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
    if (!value) throw std::runtime_error(std::string("Line ") + std::to_string(line) + ": " + expression);
}
#define CHECK(x) check(bool(x), #x, __LINE__)
Observation parse(const Data& data) {
    Observation obs; CHECK(parseAdvertisement(data.data(), data.size(), -58, 1, 2000000, obs)); return obs;
}
AccessPoint aggregate(const Data& frame) { AccessPointStore store; store.observe(parse(frame)); return store.at(0); }
struct StringSink : Sink {
    std::string value;
    bool write(const uint8_t* data, size_t n) override { value.append(reinterpret_cast<const char*>(data), n); return true; }
};
struct FailingSink : Sink { bool write(const uint8_t*, size_t) override { return false; } };
void parserTests() {
    auto f = beacon(); proprietary(f);
    CHECK(parse(f).evidence == ProprietaryIe);
    CHECK(classify(aggregate(f)) == Classification::BroadcomSignature);
    for (size_t size : {4, 8, 10, 12}) { auto other = beacon(); proprietary(other, size); CHECK(parse(other).evidence == 0); }
    CHECK(classify(aggregate(ordinaryWps())) == Classification::WpsOnly);
    CHECK(parse(ordinaryWps()).wps.manufacturer.length == 14);
    CHECK(parse(fixedUuid()).evidence == FixedUuid);
    CHECK(parse(fixedUuid(true)).evidence == FixedUuid);
    CHECK(parse(defaults()).evidence == IdentityDefaults);
    CHECK(classify(aggregate(beacon())) == Classification::NoSignature);
    CHECK(wpsState(aggregate(beacon())) == WpsState::No);
    CHECK(wpsState(aggregate(ordinaryWps())) == WpsState::Yes);
    auto hidden = parse(beacon({})); CHECK(hidden.ssidPresent && hidden.ssid.length == 0 && !hidden.malformed);
    auto binary = parse(beacon({0,0xff,'"','\\',',','\n'})); CHECK(binary.ssid.length == 6);
    char rendered[40]; renderBytes(binary.ssid.data, binary.ssid.length, rendered, sizeof(rendered));
    CHECK(std::string(rendered) == "\\x00\\xFF\"\\x5C,\\x0A");
    auto truncated = beacon(); truncated.insert(truncated.end(), {221,9,0,0x10});
    CHECK(parse(truncated).malformed);
    CHECK(classify(aggregate(truncated)) == Classification::InsufficientData);
    CHECK(wpsState(aggregate(truncated)) == WpsState::Unknown);
    auto badTlv = beacon(); wps(badTlv, {0x10,0x21,0xff,0xff,'B'});
    CHECK(parse(badTlv).malformed && parse(badTlv).evidence == 0);
    CHECK(wpsState(aggregate(badTlv)) == WpsState::Unknown);
    auto emptyWps = beacon(); wps(emptyWps, {}); CHECK(parse(emptyWps).malformed);
    proprietary(badTlv); CHECK(parse(badTlv).evidence == 0);
    auto dangling = beacon(); dangling.push_back(221); CHECK(parse(dangling).malformed);
    auto noSsid = beacon(); noSsid.erase(noSsid.begin()+36, noSsid.begin()+42); CHECK(parse(noSsid).malformed);
    auto tooLong = beacon(Data(33, 'a')); CHECK(parse(tooLong).malformed);
    auto probe = fixedUuid(); probe[0] = 0x50; CHECK(parse(probe).evidence == FixedUuid);
    for (uint8_t type : {0x40,0x08,0x88,0xc0,0xa0,0x81}) {
        auto other = f; other[0] = type; Observation o; CHECK(!parseAdvertisement(other.data(), other.size(), -50, 1, 0, o));
    }
    Observation o;
    CHECK(!parseAdvertisement(nullptr, 0, -50, 1, 0, o));
    for (size_t n = 0; n < 36; ++n) CHECK(!parseAdvertisement(f.data(), n, -50, 1, 0, o));
    for (uint8_t flag : {1,2,4,0x40,0x80}) { auto other = f; other[1] = flag; CHECK(!parseAdvertisement(other.data(), other.size(), -50, 1, 0, o)); }
    auto fragmented = f; fragmented[22] = 1; CHECK(!parseAdvertisement(fragmented.data(), fragmented.size(), -50, 1, 0, o));
    auto multicast = f; multicast[16] = 1; CHECK(!parseAdvertisement(multicast.data(), multicast.size(), -50, 1, 0, o));
    auto nullBssid = f; std::memset(nullBssid.data()+16, 0, 6); CHECK(!parseAdvertisement(nullBssid.data(), nullBssid.size(), -50, 1, 0, o));
    // A WPS attribute split over vendor elements is reassembled before TLV parsing.
    Data t; tlv(t, 0x1021, text("Broadcom")); tlv(t, 0x1023, text("BroadcomAP"));
    auto split = beacon(); wps(split, Data(t.begin(), t.begin()+7)); wps(split, Data(t.begin()+7, t.end()));
    CHECK(parse(split).evidence == IdentityDefaults);
    auto overflowing = beacon(); for (int i = 0; i < 5; ++i) wps(overflowing, Data(240, 0));
    CHECK(parse(overflowing).malformed);
    WpsIdentity w;
    CHECK(!parseWpsAttributes(nullptr, 1, w));
    CHECK(parseWpsAttributes(nullptr, 0, w));
    for (size_t n : {1,2,3}) { Data shortTlv(n, 0); CHECK(!parseWpsAttributes(shortTlv.data(), n, w)); }
    Data wrongUuid; tlv(wrongUuid, 0x1047, Data(15, 0)); CHECK(!parseWpsAttributes(wrongUuid.data(), wrongUuid.size(), w));
    // Duplicate characteristic attributes count as one distinct default field.
    auto duplicate = beacon(); Data dup; tlv(dup, 0x1021, text("Broadcom")); tlv(dup, 0x1021, text("Broadcom")); wps(duplicate, dup);
    CHECK(parse(duplicate).evidence == 0);
    for (auto pair : {std::pair<uint16_t,std::string>{0x1023,"BROADCOM"}, {0x1023,"BroadcomAP"}, {0x1024,"123456"}, {0x1011,"broadcomAP"}}) {
        auto two = beacon(); Data d; tlv(d, 0x1021, {'B','r','o','a','d','c','o','m',0,0}); tlv(d, pair.first, text(pair.second)); wps(two, d);
        CHECK(parse(two).evidence == IdentityDefaults);
    }
    auto prefix = beacon(); Data prefixTlv; tlv(prefixTlv, 0x1021, text("Broadcom" + std::string(80,'x'))); tlv(prefixTlv, 0x1024, text("1234")); wps(prefix, prefixTlv);
    CHECK(parse(prefix).evidence == 0 && parse(prefix).wps.manufacturer.truncated);
    // All strict prefixes of a valid frame are safe, including truncated IE/TLV bodies.
    for (size_t n = 36; n < f.size(); ++n) {
        auto partial = Data(f.begin(), f.begin()+n); auto p = parse(partial);
        if (p.malformed) CHECK(p.evidence == 0);
    }
}
void storeTests() {
    AccessPointStore store;
    store.observe(parse(beacon({'s','a','m','e'}, 1))); store.observe(parse(beacon({'s','a','m','e'}, 2)));
    CHECK(store.size() == 2);
    store.observe(parse(fixedUuid())); store.observe(parse(defaults())); auto f = beacon(); proprietary(f); store.observe(parse(f));
    CHECK(store.size() == 2 && store.at(0).info.evidence == 7 && store.broadcomCount() == 1);
    auto fresh = parse(beacon({},1)); fresh.rssi = -90; fresh.seenUs = 4000000; store.observe(fresh);
    CHECK(store.at(0).info.ssid.length != 0 && store.at(0).info.rssi == -90 && store.at(0).maxRssi == -58);
    CHECK(store.at(0).lastSeenUs == 4000000 && store.at(0).advertisements == 5);
    auto malformedFrame = beacon(); malformedFrame.push_back(221); store.observe(parse(malformedFrame));
    CHECK(store.at(0).malformedAdvertisements == 1 && store.at(0).info.evidence == 7);
    CHECK(store.at(0).completeAdvertisements == 5);
    // Separate complete advertisements can supply different identity defaults.
    store.clear(); Data one; tlv(one, 0x1021, text("Broadcom")); auto first = beacon(); wps(first, one); store.observe(parse(first));
    CHECK(store.at(0).info.evidence == 0);
    Data two; tlv(two, 0x1024, text("1234")); auto second = beacon(); wps(second, two); store.observe(parse(second));
    CHECK(store.at(0).info.evidence == IdentityDefaults && store.at(0).info.wps.manufacturer.length == 8);
    store.clear(); auto bad = beacon(Data(33,'x')); store.observe(parse(bad)); store.observe(parse(beacon({})));
    CHECK(store.at(0).info.ssid.length == 0 && !store.at(0).info.malformed);
    store.clear();
    for (size_t i = 1; i <= kMaxAps; ++i) CHECK(store.observe(parse(beacon({'x'}, i))));
    CHECK(!store.observe(parse(beacon({'x'}, 200))));
    CHECK(store.size() == kMaxAps && store.dropped() == 1);
    CHECK(store.observe(parse(beacon({'x'}, 1))));
    CHECK(store.at(0).advertisements == 2);
    store.clear(); CHECK(store.size() == 0 && store.dropped() == 0);
    auto vendors = beacon(); for (int i=0;i<12;++i) ie(vendors,221,{uint8_t(i),1,2,3});
    CHECK(parse(vendors).vendorCount == 8 && parse(vendors).vendorOverflow);
}
void scannerTests() {
    WifiScanner scanner; CHECK(scanner.begin());
    CHECK(mock::enabled && mock::channel == 1);
    CHECK(scanner.stats().running && scanner.stats().listenedChannels == 1);
    wifi_promiscuous_pkt_t packet{}; auto f = fixedUuid();
    packet.rx_ctrl = {0, uint16_t(f.size()+4), -61, 6}; std::memcpy(packet.payload, f.data(), f.size());
    for (size_t i=0;i<kQueueDepth+5;++i) mock::callback(&packet,WIFI_PKT_MGMT);
    CHECK(scanner.stats().received == kQueueDepth+5 && scanner.stats().queueDrops == 5);
    // Driver storage is invalid immediately after callback. Queued bytes must be independent.
    std::memset(packet.payload,0,sizeof(packet.payload)); Frame captured;
    size_t count=0;
    while(scanner.pop(captured)) { ++count; CHECK(captured.length==f.size()); CHECK(captured.bytes[0]==0x80); CHECK(captured.rssi==-61 && captured.channel==6); }
    CHECK(count==kQueueDepth);
    CHECK(!scanner.pop(captured));
    packet.rx_ctrl.sig_len = 2390; packet.payload[0] = 0x80; mock::callback(&packet, WIFI_PKT_MGMT);
    CHECK(scanner.stats().oversizeDrops == 1);
    const auto before = scanner.stats().received;
    packet.rx_ctrl.sig_len = 40; packet.payload[0] = 0x40; mock::callback(&packet,WIFI_PKT_MGMT);
    packet.payload[0] = 0x80; mock::callback(&packet,WIFI_PKT_DATA);
    packet.rx_ctrl.rx_state=1; mock::callback(&packet,WIFI_PKT_MGMT);
    CHECK(scanner.stats().received==before);
    for (unsigned channel = 2; channel <= 13; ++channel) { mock::nowUs += 400000; scanner.tick(); CHECK(mock::channel==channel); }
    mock::nowUs += 400000; scanner.tick(); CHECK(mock::channel==1 && scanner.stats().listenedChannels==0x1fff);
    CHECK(scanner.selectChannel(6)); mock::nowUs += 10000000; scanner.tick(); CHECK(mock::channel==6 && !scanner.stats().hopping);
    CHECK(!scanner.selectChannel(14)); CHECK(scanner.selectChannel(0));
    CHECK(scanner.setRunning(false)); CHECK(!mock::enabled);
    scanner.clear(); CHECK(scanner.stats().received==0 && scanner.stats().queueDrops==0);
    CHECK(scanner.setRunning(true));
    // Source-level API audit also forbids undeclared active APIs; mocks expose no such calls.
    CHECK(mock::calls.front()=="netif_init");
    mock::country.nchan = 11; WifiScanner us; CHECK(us.begin()); CHECK(us.stats().channelCount==11 && !us.selectChannel(12));
    mock::country.policy = WIFI_COUNTRY_POLICY_AUTO; WifiScanner bad; CHECK(!bad.begin());
    mock::country.policy = WIFI_COUNTRY_POLICY_MANUAL; mock::country.nchan=13;
    mock::result=ESP_FAIL; WifiScanner failed; CHECK(!failed.begin()); mock::result=ESP_OK;
}
void exportTests(const char* output) {
    AccessPointStore store; auto f = beacon({0,0xff,'"',',','\n'}); proprietary(f); store.observe(parse(f)); store.observe(parse(ordinaryWps()));
    store.observe(parse(f));
    // Same BSSID merges observations and preserves the binary SSID until a named ad arrives.
    auto other = fixedUuid(true); other[21] = 2; store.observe(parse(other));
    auto formula = beacon({'=','1','+','1'},3); store.observe(parse(formula));
    PcapRing ring; Frame frame; frame.length=f.size(); frame.timestampUs=2345678; std::memcpy(frame.bytes,f.data(),f.size());
    ring.add(frame); CHECK(ring.size()==0); ring.enable(true);
    for(size_t i=0;i<kPcapDepth+2;++i) { frame.timestampUs=2000000+i; ring.add(frame); }
    CHECK(ring.size()==kPcapDepth && ring.overwritten()==2 && ring.at(0).timestampUs==2000002);
    auto originalCount=ring.size(); frame.bytes[0]=0x08; ring.add(frame); CHECK(ring.size()==originalCount); frame.bytes[0]=0x80;
    StringSink json; ScanStats stats; stats.listenedChannels=0x1fff; stats.received=30;
    CHECK(writeJsonHeader(json,stats,"Cardputer ADV","PL",ring));
    for(size_t i=0;i<store.size();++i) CHECK(writeJsonAp(json,store.at(i),i==0));
    CHECK(writeJsonFooter(json));
    CHECK(json.value.find("broadcom_proprietary_ie")!=std::string::npos);
    FailingSink fail;
    CHECK(!writeJsonHeader(fail,stats,"Cardputer","PL",ring)); CHECK(!writeCsvAp(fail,store.at(0)));
    CHECK(!writePcapHeader(fail)); CHECK(!writePcapFrame(fail,frame));
    frame.bytes[0]=0x40; StringSink invalid; CHECK(!writePcapFrame(invalid,frame)); frame.bytes[0]=0x80;
    mock::files.clear(); mock::sdPresent=false;
    Exporter exporter; CHECK(!exporter.mount()); CHECK(!exporter.start(store,stats,ring,"Cardputer ADV"));
    CHECK(!exporter.busy()); exporter.tick(); CHECK(store.size()==3);
    mock::sdPresent=true; CHECK(exporter.mount());
    CHECK(exporter.start(store,stats,ring,"Cardputer ADV"));
    unsigned ticks=0; while(exporter.busy() && ticks++<1000) exporter.tick();
    CHECK(!exporter.busy() && ticks<1000);
    CHECK(mock::files.count("/broadcom-radar/scan-001.json"));
    CHECK(mock::files.count("/broadcom-radar/scan-001.csv"));
    CHECK(mock::files.count("/broadcom-radar/scan-001.pcap"));
    if(output) for(const char* extension : {"json","csv","pcap"}) {
        std::string key=std::string("/broadcom-radar/scan-001.")+extension;
        const auto& data=mock::files.at(key); std::ofstream file(std::string(output)+"/scan-001."+extension,std::ios::binary);
        file.write(reinterpret_cast<const char*>(data.data()),data.size()); CHECK(bool(file));
    }
    // Existing names and interrupted files must never be overwritten.
    mock::files["/broadcom-radar/scan-002.csv.part"]={1,2,3};
    CHECK(exporter.start(store,stats,ring,"Cardputer ADV")); while(exporter.busy()) exporter.tick();
    CHECK(mock::files.count("/broadcom-radar/scan-003.json"));
    CHECK(mock::files.at("/broadcom-radar/scan-002.csv.part").size()==3);
    CHECK(exporter.start(store,stats,ring,"Cardputer ADV")); mock::failWrite=true; exporter.tick();
    CHECK(!exporter.busy() && !exporter.available()); mock::failWrite=false;
    CHECK(exporter.mount()); CHECK(exporter.start(store,stats,ring,"Cardputer ADV")); mock::sdPresent=false; exporter.tick();
    CHECK(!exporter.busy()); mock::sdPresent=true;
    CHECK(exporter.mount()); mock::failRename=true; CHECK(exporter.start(store,stats,ring,"Cardputer ADV"));
    while(exporter.busy()) exporter.tick(); CHECK(!exporter.available()); mock::failRename=false;
    ring.enable(false); CHECK(ring.size()==0);
    CHECK(exporter.mount()); CHECK(exporter.start(store,stats,ring,"Cardputer ADV")); while(exporter.busy()) exporter.tick();
    CHECK(exporter.available());
    AccessPointStore empty; CHECK(exporter.start(empty,stats,ring,"Cardputer ADV")); while(exporter.busy()) exporter.tick();
    CHECK(exporter.available());
}
void corruptionTests() {
    std::mt19937 random(0x4252434d); Observation observation;
    for(size_t iteration=0;iteration<50000;++iteration) {
        Data data(random()%2400); for(auto& byte:data) byte=uint8_t(random());
        if(iteration%2==0 && data.size()>=36) { data[0]=0x80; data[1]=0; data[16]=2; data[22]=0; }
        bool accepted=parseAdvertisement(data.data(),data.size(),-80,6,iteration,observation);
        if(accepted) {
            CHECK(observation.ssid.length<=32 && observation.vendorCount<=8);
            if(observation.malformed) CHECK(observation.evidence==0);
            Observation repeat; CHECK(parseAdvertisement(data.data(),data.size(),-80,6,iteration,repeat));
            CHECK(observation.malformed==repeat.malformed && observation.evidence==repeat.evidence);
        }
        WpsIdentity identity; parseWpsAttributes(data.data(),data.size(),identity);
    }
}
void uiTests() {
    WifiScanner scanner; CHECK(scanner.begin());
    AccessPointStore store; store.observe(parse(defaults()));
    PcapRing ring; Exporter exporter; DisplayUi ui; CHECK(ui.begin());
    uint32_t rejected=0,malformed=0;
    auto tick=[&]() { mock::nowUs+=300000;ui.tick(store,scanner,exporter,ring,rejected,malformed,"Cardputer ADV");M5Cardputer.Keyboard.changed=false; };
    auto key=[&](const char* text) { M5Cardputer.Keyboard.event(text);tick(); };
    tick(); CHECK(scanner.stats().running);
    CHECK(M5Cardputer.Display.directClears==0);
    CHECK(M5Cardputer.Display.lines.size()==9);
    CHECK(M5Cardputer.Display.lines[3].find("BRCM")!=std::string::npos);
    CHECK(M5Cardputer.Display.lines[3].find("dBm")!=std::string::npos);
    CHECK(M5Cardputer.Display.backgrounds[3]==TFT_NAVY);
    CHECK(M5Cardputer.Display.lines[7].empty());
    CHECK(M5Cardputer.Display.lines[8]=="S:pause M:channel H:help");
    const auto initialPushes=M5Cardputer.Display.pushes;
    tick(); tick(); CHECK(M5Cardputer.Display.pushes==initialPushes);
    key("h"); CHECK(M5Cardputer.Display.lines[0]=="KEYBOARD HELP");
    CHECK(M5Cardputer.Display.lines[5].find("save JSON")!=std::string::npos);
    key("`"); CHECK(M5Cardputer.Display.lines[0]=="BROADCOM RADAR");
    key("s"); CHECK(!scanner.stats().running); key("S"); CHECK(scanner.stats().running);
    M5Cardputer.Keyboard.event("");M5Cardputer.Keyboard.state.enter=true;tick();
    CHECK(M5Cardputer.Display.lines[0].find("AP INFO 1/7")!=std::string::npos);
    M5Cardputer.Keyboard.event("");M5Cardputer.Keyboard.state.right=true;tick();
    CHECK(M5Cardputer.Display.lines[2].find("WHY:")!=std::string::npos);
    for(unsigned page=2;page<7;++page) {
        key("/"); CHECK(M5Cardputer.Display.lines[0].find(std::to_string(page+1)+"/7")!=std::string::npos);
    }
    key("/"); CHECK(M5Cardputer.Display.lines[0].find("1/7")!=std::string::npos);
    key(","); CHECK(M5Cardputer.Display.lines[0].find("7/7")!=std::string::npos);
    key("`");key("m");key("/");
    M5Cardputer.Keyboard.event("");M5Cardputer.Keyboard.state.enter=true;tick();
    CHECK(!scanner.stats().hopping && scanner.stats().channel==1);
    key("p"); CHECK(ring.enabled());
    mock::sdPresent=false;key("e");CHECK(!exporter.busy() && scanner.stats().running);
    mock::sdPresent=true;key("e");CHECK(exporter.busy() && !scanner.stats().running);
    key("r");CHECK(store.size()==1); // Changes are disabled during export.
    for(unsigned i=0;i<50 && exporter.busy();++i) tick();
    CHECK(!exporter.busy() && scanner.stats().running);
    key("s");key("e");while(exporter.busy())tick();CHECK(!scanner.stats().running);
    key("r");CHECK(store.size()==0 && rejected==0 && malformed==0);
    CHECK(M5Cardputer.Display.lines[4]=="Listening for networks...");
    CHECK(M5Cardputer.Display.lines[3].empty());
    for(unsigned i=1;i<=6;++i) store.observe(parse(beacon(text("Network-"+std::to_string(i)),i)));
    key("."); key("."); key("."); key("."); key(".");
    CHECK(M5Cardputer.Display.lines[3].find("Network-2")!=std::string::npos);
    CHECK(M5Cardputer.Display.lines[7].find(">NONE Network-6")!=std::string::npos);
    store.clear();
    store.observe(parse(beacon(text("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"))));
    M5Cardputer.Keyboard.event(""); M5Cardputer.Keyboard.state.enter=true; tick();
    CHECK(M5Cardputer.Display.lines[1]=="ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    CHECK(M5Cardputer.Display.lines[2]=="123456");
    CHECK(M5Cardputer.Display.lines[3]=="02:00:00:00:00:01");
    CHECK(M5Cardputer.Display.directClears==0);
    CHECK(M5Cardputer.Display.boundsOk);
    M5Canvas::failAllocation=true;
    DisplayUi noMemory; CHECK(!noMemory.begin());
    M5Canvas::failAllocation=false;
}
void uiSortingTests() {
    WifiScanner scanner; CHECK(scanner.begin());
    AccessPointStore store;
    auto waiting=beacon(text("Waiting"),1); waiting.push_back(221);
    store.observe(parse(waiting));
    store.observe(parse(beacon(text("Plain"),2)));
    auto withWps=beacon(text("With-WPS"),3);
    Data identity; tlv(identity,0x1021,text("Example Vendor")); wps(withWps,identity);
    store.observe(parse(withWps));
    auto first=beacon(text("Broadcom-A"),4); proprietary(first); store.observe(parse(first));
    auto second=beacon(text("Broadcom-B"),5); proprietary(second); store.observe(parse(second));
    store.observe(parse(beacon(text("Plain-2"),6)));
    PcapRing ring; Exporter exporter; DisplayUi ui; CHECK(ui.begin());
    uint32_t rejected=0,malformed=0;
    auto tick=[&]() { mock::nowUs+=600000;ui.tick(store,scanner,exporter,ring,rejected,malformed,"Cardputer ADV");M5Cardputer.Keyboard.changed=false; };
    auto key=[&](const char* text) { M5Cardputer.Keyboard.event(text);tick(); };
    auto enter=[&]() { M5Cardputer.Keyboard.event("");M5Cardputer.Keyboard.state.enter=true;tick(); };
    M5Cardputer.Keyboard.event(""); M5Cardputer.Keyboard.changed=false; tick();
    CHECK(M5Cardputer.Display.lines[3].find(">BRCM Broadcom-A")!=std::string::npos);
    CHECK(M5Cardputer.Display.lines[4].find("BRCM Broadcom-B")!=std::string::npos);
    CHECK(M5Cardputer.Display.lines[5].find("WPS  With-WPS")!=std::string::npos);
    CHECK(M5Cardputer.Display.lines[6].find("NONE Plain ")!=std::string::npos);
    CHECK(M5Cardputer.Display.lines[7].find("NONE Plain-2")!=std::string::npos);
    for(unsigned i=0;i<5;++i) key(".");
    CHECK(M5Cardputer.Display.lines[7].find(">WAIT Waiting")!=std::string::npos);
    enter(); CHECK(M5Cardputer.Display.lines[1]=="Waiting");
    key("`"); for(unsigned i=0;i<4;++i) key(";");
    enter(); CHECK(M5Cardputer.Display.lines[1]=="Broadcom-B");
    // New evidence can move an earlier AP ahead of the currently open AP.
    auto promoted=beacon(text("Plain"),2); proprietary(promoted); store.observe(parse(promoted)); tick();
    CHECK(M5Cardputer.Display.lines[1]=="Broadcom-B");
    key("`");
    CHECK(M5Cardputer.Display.lines[3].find("BRCM Plain ")!=std::string::npos);
    CHECK(M5Cardputer.Display.lines[5].find(">BRCM Broadcom-B")!=std::string::npos);
    key(".");
    auto completed=beacon(text("Waiting"),1); proprietary(completed); store.observe(parse(completed)); tick();
    CHECK(M5Cardputer.Display.lines[3].find("BRCM Waiting")!=std::string::npos);
    CHECK(M5Cardputer.Display.lines[7].find(">WPS  With-WPS")!=std::string::npos);
    enter(); CHECK(M5Cardputer.Display.lines[1]=="With-WPS");
    key("r"); CHECK(store.size()==0);
    store.observe(parse(beacon(text("Plain"),2))); store.observe(parse(first)); tick();
    CHECK(M5Cardputer.Display.lines[3].find(">BRCM Broadcom-A")!=std::string::npos);
    CHECK(M5Cardputer.Display.boundsOk);
}
}
int main(int argc,char** argv) {
    try {
        parserTests(); storeTests(); scannerTests(); exportTests(argc>1?argv[1]:nullptr); uiTests(); uiSortingTests(); corruptionTests();
        std::cout << "PASS: " << checks << " checks; 50,000 deterministic corrupt frames\n";
    } catch(const std::exception& e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; }
}
