#pragma once
#include "Serialization.h"
#include <FS.h>
#include <SPI.h>
namespace radar {
class Exporter {
public:
    bool mount();
    bool available() const { return available_; }
    bool start(const AccessPointStore& store, const ScanStats& stats, const PcapRing& ring, const char* hardware);
    void tick();
    bool busy() const { return phase_ != Phase::Idle; }
    const char* message() const { return message_; }
private:
    enum class Phase { Idle, Json, Csv, Pcap, Finish };
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
    void filename(char* path, size_t capacity, const char* ext, bool partial) const;
    SPIClass spi_{FSPI};
    fs::File file_;
    const AccessPointStore* store_ = nullptr;
    const PcapRing* ring_ = nullptr;
    Phase phase_ = Phase::Idle;
    size_t index_ = 0;
    unsigned sequence_ = 0;
    bool available_ = false;
    char message_[64] = "SD unavailable";
};
}
