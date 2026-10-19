#include "Export.h"
#include <SD.h>
#include <cstdio>
#include <cstring>
namespace radar {
bool Exporter::FileSink::write(const uint8_t* data, size_t size) {
    while (size) {
        size_t n = sizeof(buffer_) - used_;
        if (n > size) n = size;
        std::memcpy(buffer_ + used_, data, n); used_ += n; data += n; size -= n;
        if (used_ == sizeof(buffer_) && !flush()) return false;
    }
    return true;
}
bool Exporter::FileSink::flush() {
    if (used_ && file_.write(buffer_, used_) != used_) return false;
    used_ = 0;
    return file_ && file_.getWriteError() == 0;
}
bool Exporter::mount() {
    if (busy()) return available_;
    // The expansion connector shares this bus on ADV; keep its CS inactive.
#if RADAR_ADV
    pinMode(5, OUTPUT); digitalWrite(5, HIGH);
#endif
    spi_.begin(40, 39, 14, 12);
    available_ = SD.begin(12, spi_, 10000000) && SD.cardType() != CARD_NONE;
    if (available_ && !SD.exists("/broadcom-radar")) available_ = SD.mkdir("/broadcom-radar");
    std::snprintf(message_, sizeof(message_), "%s", available_ ? "SD ready" : "SD unavailable; scan continues");
    return available_;
}
void Exporter::filename(char* path, size_t size, const char* ext, bool partial) const {
    std::snprintf(path, size, "/broadcom-radar/scan-%03u.%s%s", sequence_, ext, partial ? ".part" : "");
}
bool Exporter::open(const char* ext) {
    char path[80]; filename(path, sizeof(path), ext, true);
    file_ = SD.open(path, FILE_WRITE);
    return bool(file_);
}
bool Exporter::finishFile(const char* ext) {
    file_.flush(); const bool good = file_.getWriteError() == 0; file_.close();
    if (!good) return false;
    char src[80], dst[80]; filename(src, sizeof(src), ext, true); filename(dst, sizeof(dst), ext, false);
    return !SD.exists(dst) && SD.rename(src, dst);
}
void Exporter::fail(const char* reason) {
    file_.close(); phase_ = Phase::Idle; available_ = false;
    std::snprintf(message_, sizeof(message_), "%s", reason);
}
bool Exporter::start(const AccessPointStore& store, const ScanStats& stats, const PcapRing& ring, const char* hardware) {
    if (busy()) return false;
    if (!available_ && !mount()) return false;
    // Never overwrite a prior export, including interrupted .part files.
    for (; sequence_ < 9999;) {
        ++sequence_; bool exists = false; char path[80];
        for (const char* ext : {"json", "csv", "pcap"}) for (bool partial : {false, true}) {
            filename(path, sizeof(path), ext, partial); exists |= SD.exists(path);
        }
        if (!exists) break;
    }
    if (sequence_ >= 9999) { fail("Export names exhausted"); return false; }
    store_ = &store; ring_ = &ring; index_ = 0;
    if (!open("json")) { fail("SD open failed"); return false; }
    FileSink sink(file_);
    if (!writeJsonHeader(sink, stats, hardware, RADAR_COUNTRY, ring) || !sink.flush()) { fail("SD write failed"); return false; }
    phase_ = Phase::Json;
    std::snprintf(message_, sizeof(message_), "Export scan-%03u (capture paused)", sequence_);
    return true;
}
void Exporter::tick() {
    if (!busy()) return;
    FileSink sink(file_);
    bool good = true;
    switch (phase_) {
    case Phase::Json:
        if (index_ < store_->size()) { good = writeJsonAp(sink, store_->at(index_), index_ == 0); ++index_; }
        else {
            good = writeJsonFooter(sink) && sink.flush() && finishFile("json") && open("csv");
            if (good) { FileSink csv(file_); good = writeCsvHeader(csv) && csv.flush(); phase_ = Phase::Csv; index_ = 0; }
        }
        break;
    case Phase::Csv:
        if (index_ < store_->size()) good = writeCsvAp(sink, store_->at(index_++));
        else {
            good = sink.flush() && finishFile("csv");
            if (good && ring_->enabled()) {
                good = open("pcap");
                if (good) { FileSink pcap(file_); good = writePcapHeader(pcap) && pcap.flush(); }
                phase_ = Phase::Pcap; index_ = 0;
            } else phase_ = Phase::Finish;
        }
        break;
    case Phase::Pcap:
        if (index_ < ring_->size()) good = writePcapFrame(sink, ring_->at(index_++));
        else { good = sink.flush() && finishFile("pcap"); phase_ = Phase::Finish; }
        break;
    case Phase::Finish:
        phase_ = Phase::Idle;
        std::snprintf(message_, sizeof(message_), "Saved scan-%03u.json / csv%s", sequence_, ring_->enabled() ? " / pcap" : "");
        return;
    default: return;
    }
    // A phase transition may have closed the file. All transition buffers were flushed above.
    if (good && (sink.flush() || phase_ == Phase::Finish)) return;
    fail("SD export failed; partial files kept");
}
}
