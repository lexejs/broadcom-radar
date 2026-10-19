#pragma once
#include "AccessPointStore.h"
namespace radar {
class Sink {
public:
    virtual ~Sink() = default;
    virtual bool write(const uint8_t* bytes, size_t length) = 0;
};
bool writeJsonHeader(Sink& sink, const ScanStats& stats, const char* hardware,
                     const char* country, const PcapRing& ring);
bool writeJsonAp(Sink& sink, const AccessPoint& ap, bool first);
bool writeJsonFooter(Sink& sink);
bool writeCsvHeader(Sink& sink);
bool writeCsvAp(Sink& sink, const AccessPoint& ap);
bool writePcapHeader(Sink& sink);
bool writePcapFrame(Sink& sink, const Frame& frame);
}
