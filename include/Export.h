#pragma once
#include "Serialization.h"
#include "WpsProbe.h"
#include <FS.h>
#include <SPI.h>
namespace radar {
class Exporter {
public:
    bool mount();
    bool available() const { return available_; }
    bool start(const AccessPointStore& store, const ScanStats& stats, const PcapRing& ring, const char* hardware);
    bool needsDetection(const Observation& observation, const AccessPoint* aggregate, uint64_t nowUs) const;
    bool saveDetection(const Observation& observation, const AccessPoint* aggregate, const Frame& frame,
                       const ScanStats& stats, const char* hardware, const Frame* companion = nullptr);
    bool saveProbe(const WpsProbe& probe, const char* hardware);
    void tick();
    bool busy() const { return phase_ != Phase::Idle; }
    const char* message() const { return message_; }
    const char* probeMessage(const WpsProbe& probe) const;
    bool probeSaved(const WpsProbe& probe) const;
private:
    enum class Phase { Idle, Json, Csv, Pcap, PcapNg, Finish };
    class FileSink : public Sink {
    public:
        explicit FileSink(fs::File& file) : file_(file) {}
        bool write(const uint8_t* bytes, size_t size) override;
        bool flush();
    private:
        fs::File& file_;
        uint8_t buffer_[512]{};
        size_t used_ = 0;
    };
    void fail(const char* reason);
    bool open(const char* extension);
    bool finishFile(const char* extension);
    bool publishFile(const char* extension);
    bool indexSequences();
    bool nextSequence();
    void filename(char* path, size_t capacity, const char* ext, bool partial) const;
    struct SavedDetection {
        uint8_t bssid[6]{}, evidence = 0, fields = 0;
    };
    SavedDetection saved_[kMaxAps]{};
    size_t savedCount_ = 0, savedNext_ = 0;
    uint64_t retryAfterUs_ = 0;
    SPIClass spi_{FSPI};
    fs::File file_;
    const AccessPointStore* store_ = nullptr;
    const PcapRing* ring_ = nullptr;
    Phase phase_ = Phase::Idle;
    size_t index_ = 0;
    unsigned sequence_ = 0;
    unsigned detectionSequence_ = 0;
    bool gps_ = false;
    bool detection_ = false;
    bool probe_ = false;
    unsigned probeSequence_ = 0;
    bool available_ = false;
    bool namesIndexed_ = false;
    char message_[64] = "SD unavailable";
    const WpsProbe* reportProbe_ = nullptr;
    uint32_t reportAttempt_ = 0;
    bool reportSaved_ = false;
    char reportMessage_[64] = "Report: pending";
};
}
