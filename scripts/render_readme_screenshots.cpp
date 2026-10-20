// Capture production UI rows with synthetic networks and existing host backends.
#include "DisplayUi.h"
#include "Fixtures.h"
#include <cassert>
#include <iomanip>
#include <iostream>

int main() {
    using namespace radar;
    using namespace fixtures;
    WifiScanner scanner;
    assert(scanner.begin());
    AccessPointStore store;
    auto add = [&](const char* name, uint8_t suffix, int8_t signal, unsigned kind) {
        auto frame = beacon(text(name), suffix);
        if (kind < 2) proprietary(frame);
        if (kind == 0 || kind == 2) {
            Data fields;
            tlv(fields, 0x1021, text(kind == 0 ? "Broadcom" : "Example Vendor"));
            tlv(fields, 0x1023, text(kind == 0 ? "BroadcomAP" : "Demo AP"));
            if (kind == 0) tlv(fields, 0x1047, {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,0xbb});
            wps(frame, fields);
        }
        if (kind == 4) wps(frame, {0x10, 0x21, 0x00, 0x10, 'X'});
        Observation observation;
        assert(parseAdvertisement(frame.data(), frame.size(), signal, 6, mock::nowUs, observation));
        assert(store.observe(observation));
    };
    add("Demo BRCM", 1, -43, 0);
    add("Demo Radio", 2, -57, 1);
    add("Demo WPS", 3, -62, 2);
    add("Demo Guest", 4, -71, 3);
    add("Demo Pending", 5, -80, 4);
    assert(store.at(0).info.evidence == (ProprietaryIe | FixedUuid | IdentityDefaults));
    assert(classify(store.at(4)) == Classification::InsufficientData);
    PcapRing ring;
    Exporter exporter;
    assert(exporter.mount());
    DisplayUi ui;
    assert(ui.begin());
    uint32_t rejected = 0, malformed = 1;
    auto tick = [&]() {
        mock::nowUs += 10000;
        ui.tick(store, scanner, exporter, ring, rejected, malformed, "Cardputer ADV");
        M5Cardputer.Keyboard.changed = false;
        M5Cardputer.Keyboard.state = {};
        assert(M5Cardputer.Display.boundsOk);
    };
    auto enter = [&]() {
        M5Cardputer.Keyboard.changed = true;
        M5Cardputer.Keyboard.state.enter = true;
        tick();
    };
    bool first = true;
    auto capture = [&](const char* name) {
        const auto& display = M5Cardputer.Display;
        assert(display.lines.size() == 9);
        if (!first) std::cout << ',';
        first = false;
        std::cout << "{\"file\":" << std::quoted(name) << ",\"rows\":[";
        for (size_t row = 0; row < 9; ++row) {
            if (row) std::cout << ',';
            std::cout << "{\"text\":" << std::quoted(display.lines[row])
                      << ",\"foreground\":" << display.foregrounds[row]
                      << ",\"background\":" << display.backgrounds[row] << '}';
        }
        std::cout << "]}";
    };
    std::cout << "{\"firmware\":" << std::quoted(kFirmwareVersion) << ",\"screens\":[";
    tick();
    capture("network-list.png");
    enter();
    capture("network-details.png");
    enter();
    capture("detection-evidence.png");
    M5Cardputer.Keyboard.event("b");
    tick();
    capture("screen-settings.png");
    std::cout << "]}\n";
}
