#pragma once
#include "WpsProbe.h"
#if RADAR_WPS_PROBE
#include "WifiScanner.h"
#include "Export.h"
namespace radar {
class WpsProbeRadio {
public:
    bool tick(WpsProbe& probe, WifiScanner& scanner, Exporter& exporter, Frame& scratch, const char* hardware);
private:
    ScanStats previous_;
    bool prepared_ = false;
    bool macTouched_ = false;
    uint8_t originalMac_[6]{};
};
}
#endif
