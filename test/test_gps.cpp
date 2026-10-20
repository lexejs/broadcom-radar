#include "DisplayUi.h"
#include "Fixtures.h"
#include "SD.h"
#include <fstream>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <stdexcept>
using namespace radar;
using namespace fixtures;
namespace {
unsigned checks = 0;
#define CHECK(value) do { ++checks; if (!(value)) throw std::runtime_error("GPS line " + std::to_string(__LINE__) + ": " #value); } while (false)
struct Input : GpsInput {
    std::string bytes;
    unsigned starts = 0, stops = 0, discards = 0, reads = 0;
    bool ready = true;
    bool start(uint8_t, uint32_t) override { ++starts; return ready; }
    void stop() override { ++stops; }
    int available() override { return bytes.size(); }
    int read() override { ++reads; if (bytes.empty()) return -1; int c=uint8_t(bytes[0]); bytes.erase(0,1); return c; }
    void discard() override { ++discards; bytes.clear(); }
};
std::string nmea(const std::string& body) {
    uint8_t sum = 0; for (auto c : body) sum ^= c;
    char suffix[8]; std::snprintf(suffix, sizeof(suffix), "*%02X\r\n", sum);
    return "$" + body + suffix;
}
const char* example = "GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W";
GeoFix gpsTests() {
    Input input; GpsTracker gps(input); uint64_t now = 1000000;
    gps.tick(now); CHECK(!gps.enabled() && !input.starts && !input.stops);
    CHECK(!gps.configure(true, 5, 9600) && !gps.configure(true, 2, 12345));
    CHECK(gps.configure(true, 2, 9600)); gps.tick(now); CHECK(input.starts == 1);
    auto feed = [&](const std::string& text) {
        input.bytes += text;
        while (input.available()) { const auto reads=input.reads; now+=1000; gps.tick(now); CHECK(input.reads - reads <= 64); }
    };
    feed(nmea(example)); auto first = gps.at(now);
    CHECK(first.validAt(now) && gps.fixes() == 1);
    CHECK(first.latitudeE7 == 481173000 && first.longitudeE7 == 115166666);
    char text[32]; formatGpsUtc(first, text, sizeof(text)); CHECK(std::string(text) == "1994-03-23T12:35:19Z");
    CHECK(!gps.at(first.receivedUs - 1).receivedUs);
    CHECK(gps.at(first.receivedUs + 10000000).receivedUs && !gps.at(first.receivedUs + 10000001).receivedUs);
    feed(nmea("GNRMC,123520.123,A,0000.0001,S,00000.0001,W,0,0,290224,,,A"));
    CHECK(gps.at(now).latitudeE7 == -16 && gps.at(now).longitudeE7 == -16);
    formatCoordinate(-16, text, sizeof(text)); CHECK(std::string(text) == "-0.0000016");
    CHECK(gps.at(first.receivedUs).latitudeE7 == first.latitudeE7); // Earlier queued frame uses the earlier fix.
    auto bad = nmea(example); bad[bad.size()-4] = bad[bad.size()-4] == '0' ? '1' : '0';
    const auto accepted = gps.fixes(); feed(bad); CHECK(gps.fixes() == accepted && gps.at(now).receivedUs);
    feed(nmea("GPRMC,123519,V,,,,,,,230394,,,N")); CHECK(!gps.at(now).receivedUs);
    for (const auto* invalid : {
             "GPRMC,123519,A,4807.038,N,01131.000,E,0,0,310224,,,A",
             "GPRMC,246000,A,4807.038,N,01131.000,E,0,0,230394,,,A",
             "GPRMC,123519,A,9060.0,N,01131.000,E,0,0,230394,,,A",
             "GPRMC,123519,A,4807.038,X,01131.000,E,0,0,230394,,,A",
             "GPRMC,123519,A,4807.038,N,18100.000,E,0,0,230394,,,A",
             "GPRMC,123519,A,4807.038,N,01131.000,E,0,0,230394,,,S",
             "GPRMC,123519,A,4807.038,N,01131.000,E,0,0,230394,,,AB"}) {
        feed(nmea(invalid)); CHECK(!gps.at(now).receivedUs);
    }
    feed("$" + std::string(200, 'x') + "\n"); CHECK(gps.rejected() >= 8);
    feed(nmea("GPRMC,000000,A,9000.0,N,18000.0,E,0,0,010180,,,A"));
    CHECK(gps.at(now).latitudeE7 == 900000000 && gps.at(now).longitudeE7 == 1800000000);
    feed(nmea(example)); first = gps.at(now);
    feed(nmea("GPGGA,ignored")); CHECK(gps.at(now).receivedUs == first.receivedUs);
    input.bytes = nmea(example); now+=500000; gps.tick(now);
    CHECK(input.discards == 1 && !gps.at(now).receivedUs);
    feed(nmea(example)); CHECK(gps.at(now).receivedUs);
    CHECK(gps.configure(true,1,38400)); CHECK(!gps.at(now).receivedUs); gps.tick(++now); CHECK(input.starts == 2);
    CHECK(gps.configure(false,1,38400)); gps.tick(++now); CHECK(input.stops == 1 && !gps.at(now).receivedUs);
    input.ready = false; CHECK(gps.configure(true,1,38400)); gps.tick(++now);
    CHECK(gps.error() && !gps.enabled()); gps.tick(++now); CHECK(input.starts == 3);
    input.ready = true; CHECK(gps.configure(true,1,38400)); gps.tick(++now); feed(nmea(example));
    CHECK(!gps.error() && gps.at(now).receivedUs);
    return gps.at(now);
}
void writeFiles(const char* output, const char* prefix, const char* remote, bool ng) {
    if (!output) return;
    for (const char* ext : {"json", "csv", "pcap", "pcapng"}) {
        if (!ng && std::string(ext) == "pcapng") continue;
        const auto& bytes = mock::files.at(std::string("/broadcom-radar/") + remote + "." + ext);
        std::ofstream file(std::string(output) + "/" + prefix + "." + ext, std::ios::binary);
        file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); CHECK(bool(file));
    }
}
void exportTests(const GeoFix& fix, const char* output) {
    mock::files.clear(); mock::sdPresent = true;
    auto data = beacon(); proprietary(data); Frame frame;
    frame.length = data.size(); std::memcpy(frame.bytes, data.data(), data.size());
    frame.timestampUs = fix.receivedUs + 100000; frame.channel = 1; frame.receiver = fix;
    Observation obs; CHECK(parseAdvertisement(frame.bytes, frame.length, -55, 1, frame.timestampUs, obs)); obs.receiver = fix;
    AccessPointStore store; const auto* ap = store.observe(obs); PcapRing ring; ring.enable(true);
    Frame previous = frame; previous.timestampUs = fix.receivedUs - 1; previous.receiver = {}; ring.add(previous); ring.add(frame);
    CHECK(ring.geotagged()); ScanStats stats; stats.nowUs = frame.timestampUs;
    Exporter exporter; CHECK(exporter.mount() && exporter.start(store,stats,ring,"Cardputer ADV"));
    while (exporter.busy()) exporter.tick();
    CHECK(exporter.available() && std::string(exporter.message()).find("J/C/P/G") != std::string::npos);
    writeFiles(output,"gps-scan-001","scan-001",true);
    CHECK(exporter.saveDetection(obs,ap,frame,stats,"Cardputer ADV"));
    writeFiles(output,"gps-detection-001","brcm-001",true);
    // A new observation without a fix must not inherit old coordinates.
    obs.receiver = {}; ++obs.seenUs; store.observe(obs); CHECK(!store.at(0).info.receiver.receivedUs);
    mock::files["/broadcom-radar/scan-002.pcapng.part"] = {1,2,3};
    CHECK(exporter.start(store,stats,ring,"Cardputer ADV")); while (exporter.busy()) exporter.tick();
    CHECK(mock::files.count("/broadcom-radar/scan-003.json") && mock::files.at("/broadcom-radar/scan-002.pcapng.part").size() == 3);
    mock::failRenamePath = "/broadcom-radar/scan-004.pcapng";
    CHECK(exporter.start(store,stats,ring,"Cardputer ADV")); while (exporter.busy()) exporter.tick();
    CHECK(!exporter.available() && mock::files.count("/broadcom-radar/scan-004.pcapng.part"));
    mock::failRenamePath.clear(); CHECK(exporter.mount());
    obs.evidence |= FixedUuid; ap = store.observe(obs); stats.nowUs += 6000000;
    mock::failRenamePath = "/broadcom-radar/brcm-002.pcapng";
    CHECK(!exporter.saveDetection(obs,ap,frame,stats,"Cardputer ADV"));
    CHECK(!mock::files.count("/broadcom-radar/brcm-002.json") && mock::files.count("/broadcom-radar/brcm-002.json.part"));
    mock::failRenamePath.clear(); stats.nowUs += 6000000;
    CHECK(exporter.saveDetection(obs,ap,frame,stats,"Cardputer ADV"));
    ring.enable(false); CHECK(exporter.start(store,stats,ring,"Cardputer ADV")); while (exporter.busy()) exporter.tick();
    CHECK(!mock::files.count("/broadcom-radar/scan-005.pcapng"));
}
void uiTests() {
    Input input; GpsTracker gps(input); DisplayUi ui; CHECK(ui.begin()); ui.attachGps(gps);
    WifiScanner scanner; CHECK(scanner.begin()); AccessPointStore store; PcapRing ring; Exporter exporter;
    uint32_t rejected=0, malformed=0;
    auto tick=[&]() { mock::nowUs+=1000; ui.tick(store,scanner,exporter,ring,rejected,malformed,"ADV"); M5Cardputer.Keyboard.changed=false; };
    auto key=[&](const char* key) { M5Cardputer.Keyboard.event(key); tick(); M5Cardputer.Keyboard.event(""); tick(); };
    key("g"); CHECK(M5Cardputer.Display.lines[0]=="GROVE GPS" && !gps.enabled());
    key("/"); CHECK(gps.enabled()); key("."); key("/"); CHECK(gps.pin()==1);
    key("."); key(","); CHECK(gps.baud()==4800); key("/"); CHECK(gps.baud()==9600);
    key("h"); CHECK(M5Cardputer.Display.lines[0]=="GPS HELP"); key("`");
    CHECK(M5Cardputer.Display.lines[0]=="GROVE GPS");
    key("l"); key("/"); CHECK(gps.baud()==9600); // Wake key cannot change the GPS configuration.
    key("`"); CHECK(M5Cardputer.Display.lines[0].find("BRCM-RDR")==0 && M5Cardputer.Display.boundsOk);
}
}
int main(int argc,char** argv) {
    try {
        const auto fix=gpsTests(); exportTests(fix,argc>1?argv[1]:nullptr); uiTests();
        std::cout << "PASS: " << checks << " GPS assertions; simulated NMEA/UART, no module calibration\n";
    } catch (const std::exception& error) { std::cerr << "FAIL: " << error.what() << '\n'; return 1; }
}
