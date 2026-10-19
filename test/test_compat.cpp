#include "Fixtures.h"
#include "DriverCompat.h"
#include "WpsProbeRadio.h"
#include "SD.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace radar;
using namespace fixtures;
namespace {
size_t checks = 0, stockCalls = 0;
int stockFailure = 0;
void check(bool value, const char* expression, int line) {
    ++checks;
    if (!value) throw std::runtime_error(std::string("Line ") + std::to_string(line) + ": " + expression);
}
#define CHECK(x) check(bool(x), #x, __LINE__)
const uint8_t station[] = {2,0,0,0,0,0xee};
Frame frame;
Data advertisement() {
    auto bytes = beacon(); Data version; tlv(version,0x104a,{0x10}); wps(bytes,version); return bytes;
}
Observation target(const Data& bytes) {
    Observation result; CHECK(parseAdvertisement(bytes.data(),bytes.size(),-55,6,mock::nowUs,result)); return result;
}
Frame& raw(const Data& bytes) {
    frame.length = bytes.size(); frame.channel = 6; frame.timestampUs = ++mock::nowUs; frame.rssi = -55;
    std::memcpy(frame.bytes,bytes.data(),bytes.size()); return frame;
}
Data response(uint8_t control, size_t body) {
    Data bytes(24 + body); bytes[0] = control;
    const uint8_t bssid[] = {2,0,0,0,0,1};
    std::memcpy(bytes.data()+4,station,6); std::memcpy(bytes.data()+10,bssid,6); std::memcpy(bytes.data()+16,bssid,6);
    return bytes;
}
Data eap(const Data& payload) {
    auto bytes = response(8,12+payload.size()); bytes[1] = 2;
    const uint8_t snap[] = {0xaa,0xaa,3,0,0,0,0x88,0x8e,1,0};
    std::memcpy(bytes.data()+24,snap,sizeof(snap)); bytes[34] = payload.size() >> 8; bytes[35] = payload.size();
    std::memcpy(bytes.data()+36,payload.data(),payload.size()); return bytes;
}
void diagnosticTests() {
    WpsProbe probe; const auto bytes = advertisement(); CHECK(probe.request(target(bytes))); probe.begin(station,mock::nowUs);
    auto malformed = bytes; malformed.push_back(221); malformed.push_back(200); probe.receive(raw(malformed));
    auto other = beacon({'O','t','h','e','r'}); probe.receive(raw(other));
    probe.receive(raw(beacon()));
    auto& wrongChannel = raw(bytes); wrongChannel.channel = 5; probe.receive(wrongChannel);
    auto& stale = raw(bytes); stale.timestampUs = probe.result().startedUs - 1; probe.receive(stale);
    CHECK(probe.result().malformed == 1 && probe.result().wrongSsid == 1 && probe.result().noWps == 1);
    CHECK(probe.result().wrongChannel == 1 && probe.result().stale == 1);
    probe.tick(probe.result().startedUs + 9999999); CHECK(probe.busy());
    probe.tick(probe.result().startedUs + 10000000); CHECK(probe.done() && probe.result().reason == ProbeReason::NoWps);
    CHECK(probe.result().txAttempts == 0 && probe.result().lastRssi == -55);
}
void guardTests() {
    WpsProbe probe; auto bytes = advertisement(); CHECK(probe.request(target(bytes))); probe.begin(station,mock::nowUs);
    probe.receive(raw(bytes)); CHECK(probe.pending(frame)); const auto original = frame;
    for (unsigned change = 0; change < 9; ++change) {
        frame = original;
        if (change == 0) frame.bytes[0] = 0x80;
        if (change == 1) frame.bytes[1] = 0x40;
        if (change == 2) frame.bytes[4] ^= 1;
        if (change == 3) frame.bytes[10] ^= 1;
        if (change == 4) frame.bytes[16] ^= 1;
        if (change == 5) frame.bytes[26] = 2;
        if (change == 6) frame.length = 29;
        if (change == 7) frame.bytes[22] |= 1;
        if (change == 8) frame.bytes[3] = 1;
        const auto before = stockCalls; auto result = transmitCompatible(frame,probe);
        CHECK(result.error == ESP_ERR_INVALID_ARG && !result.applied && stockCalls == before);
    }
    frame = original; const auto before = stockCalls; auto result = transmitCompatible(frame,probe);
    CHECK(result.error == 0 && result.applied && result.stockError == ESP_ERR_INVALID_ARG && stockCalls == before + 1);
    // The global entry point still rejects the same frame outside its synchronous authorized call.
    CHECK(ieee80211_raw_frame_sanity_check(WIFI_IF_STA,frame.bytes,frame.length,true) == ESP_ERR_INVALID_ARG);
    stockFailure = ESP_ERR_INVALID_STATE; result = transmitCompatible(frame,probe);
    CHECK(result.error == ESP_ERR_INVALID_STATE && !result.applied); stockFailure = 0;
    // AP association rejection is recorded, without advancing to EAP.
    probe.transmitted(0,++mock::nowUs); auto auth = response(0xb0,6); auth[26] = 2; probe.receive(raw(auth));
    CHECK(probe.pending(frame)); frame.bytes[29] = 255; result = transmitCompatible(frame,probe);
    CHECK(result.error == ESP_ERR_INVALID_ARG && !result.applied);
    CHECK(probe.pending(frame)); result = transmitCompatible(frame,probe); CHECK(result.applied && !result.error);
    probe.transmitted(0,++mock::nowUs); auto rejected = response(0x10,6); rejected[26] = 17; probe.receive(raw(rejected));
    CHECK(probe.result().reason == ProbeReason::ApRejected && probe.result().apStatus == 17);
}
void deliver(WifiScanner& scanner, WpsProbe& probe, const Data& bytes, int type = WIFI_PKT_MGMT) {
    wifi_promiscuous_pkt_t packet{}; packet.rx_ctrl = {0,uint16_t(bytes.size()+4),-55,mock::channel};
    std::memcpy(packet.payload,bytes.data(),bytes.size()); ++mock::nowUs;
    mock::callback(&packet,wifi_promiscuous_pkt_type_t(type));
    CHECK(scanner.pop(frame)); probe.receive(frame);
}
void sessionTest(const char* output) {
    WifiScanner scanner; CHECK(scanner.begin()); WpsProbe probe; WpsProbeRadio radio; Exporter exporter;
    auto bytes = advertisement(); CHECK(probe.request(target(bytes)));
    CHECK(!radio.tick(probe,scanner,exporter,frame,"Cardputer ADV"));
    deliver(scanner,probe,bytes); CHECK(!radio.tick(probe,scanner,exporter,frame,"Cardputer ADV"));
    auto auth = response(0xb0,6); auth[26] = 2;
    deliver(scanner,probe,auth); CHECK(!radio.tick(probe,scanner,exporter,frame,"Cardputer ADV"));
    deliver(scanner,probe,response(0x10,6)); CHECK(!radio.tick(probe,scanner,exporter,frame,"Cardputer ADV"));
    deliver(scanner,probe,eap({1,7,0,5,1}),WIFI_PKT_DATA); CHECK(!radio.tick(probe,scanner,exporter,frame,"Cardputer ADV"));
    deliver(scanner,probe,eap({1,8,0,14,0xfe,0,0x37,0x2a,0,0,0,1,1,0}),WIFI_PKT_DATA);
    CHECK(!radio.tick(probe,scanner,exporter,frame,"Cardputer ADV"));
    CHECK(probe.restoring() && probe.result().reason == ProbeReason::TransportReady);
    CHECK(probe.result().wscStartReceived && probe.result().verdict == ProbeVerdict::Unknown);
    CHECK(probe.result().txAttempts == 5 && probe.result().txAccepted == 5 && probe.result().cleanupAccepted);
    CHECK(!probe.pending(frame));
    CHECK(scanner.stats().hopping && scanner.stats().running);
    // Normal capture admits a different AP after restoring the management-only filter.
    auto other = beacon(); other[15] = other[21] = 9; deliver(scanner,probe,other);
    CHECK(radio.tick(probe,scanner,exporter,frame,"Cardputer ADV"));
    CHECK(probe.done() && probe.result().restored && probe.result().scanRxFrames == 1);
    CHECK(mock::files.count("/broadcom-radar/test-001.json"));
    for (unsigned i = 0; i < probe.result().txAttempts; ++i) {
        const auto& tx = probe.result().tx[i]; CHECK(tx.stage != ProbeStage::Differential);
        CHECK(tx.compatibilityApplied == (i == 0 || i == 1 || i == 4));
    }
    if (output) for (const char* ext : {"json","pcap"}) {
        const auto& data = mock::files.at(std::string("/broadcom-radar/test-001.")+ext);
        std::ofstream file(std::string(output)+"/transport-001."+ext,std::ios::binary);
        file.write(reinterpret_cast<const char*>(data.data()),data.size()); CHECK(bool(file));
    }
}
}
extern "C" int radar_stock_raw_frame_check(int, const void* buffer, int, bool) {
    ++stockCalls;
    if (stockFailure) return stockFailure;
    return (static_cast<const uint8_t*>(buffer)[0] & 0x0c) == 0 ? ESP_ERR_INVALID_ARG : 0;
}
int main(int argc, char** argv) {
    try {
        mock::txResult = 0; mock::files.clear();
        diagnosticTests(); guardTests(); sessionTest(argc > 1 ? argv[1] : nullptr);
        std::cout << "PASS: " << checks << " scoped compatibility and transport-only assertions; RF not calibrated\n";
    } catch (const std::exception& e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; }
}
