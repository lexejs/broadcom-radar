#include "Export.h"
#include <SD.h>
#include <cstdio>
#include <cstring>
namespace radar {
namespace {
uint8_t identityFields(const WpsIdentity& identity) {
    return (identity.manufacturer.length ? 1 : 0) | (identity.modelName.length ? 2 : 0) |
           (identity.modelNumber.length ? 4 : 0) | (identity.deviceName.length ? 8 : 0) |
           (identity.serialNumber.length ? 16 : 0) | (identity.uuidE.length ? 32 : 0) |
           (identity.uuidR.length ? 64 : 0);
}
}
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
    namesIndexed_ = false;
    // SD.begin() reuses its cached mount after an I/O failure. Retry from a clean bus state.
    SD.end();
    spi_.end();
    // The expansion connector shares this bus on ADV; keep its CS inactive.
#if RADAR_ADV
    pinMode(5, OUTPUT); digitalWrite(5, HIGH);
#endif
    pinMode(12, OUTPUT); digitalWrite(12, HIGH);
    spi_.begin(40, 39, 14, 12);
    available_ = SD.begin(12, spi_, 10000000) && SD.cardType() != CARD_NONE;
    if (available_ && !SD.exists("/broadcom-radar")) available_ = SD.mkdir("/broadcom-radar");
    std::snprintf(message_, sizeof(message_), "%s", available_ ? "SD ready" : "SD unavailable");
    return available_;
}
void Exporter::filename(char* path, size_t size, const char* ext, bool partial) const {
    std::snprintf(path, size, "/broadcom-radar/%s-%03u.%s%s", probe_ ? "test" : detection_ ? "brcm" : "scan",
                  probe_ ? probeSequence_ : detection_ ? detectionSequence_ : sequence_, ext, partial ? ".part" : "");
}
bool Exporter::open(const char* ext) {
    char path[80]; filename(path, sizeof(path), ext, true);
    file_ = SD.open(path, FILE_WRITE);
    return bool(file_);
}
bool Exporter::finishFile(const char* ext) {
    file_.flush(); const bool good = file_.getWriteError() == 0; file_.close();
    if (!good) return false;
    return publishFile(ext);
}
bool Exporter::publishFile(const char* ext) {
    char src[80], dst[80]; filename(src, sizeof(src), ext, true); filename(dst, sizeof(dst), ext, false);
    return !SD.exists(dst) && SD.rename(src, dst);
}
void Exporter::fail(const char* reason) {
    file_.close(); phase_ = Phase::Idle; available_ = false;
    std::snprintf(message_, sizeof(message_), "%s", reason);
}
bool Exporter::start(const AccessPointStore& store, const ScanStats& stats, const PcapRing& ring, const char* hardware) {
    if (busy()) return false;
    detection_ = probe_ = false;
    if (!available_ && !mount()) return false;
    if (!nextSequence()) return false;
    store_ = &store; ring_ = &ring; index_ = 0; gps_ = ring.enabled() && ring.geotagged();
    if (!open("json")) { fail("SD open failed"); return false; }
    FileSink sink(file_);
    if (!writeJsonHeader(sink, stats, hardware, stats.country, ring) || !sink.flush()) { fail("SD write failed"); return false; }
    phase_ = Phase::Json;
    std::snprintf(message_, sizeof(message_), "Saving scan-%03u; paused", sequence_);
    return true;
}
bool Exporter::indexSequences() {
    auto directory = SD.open("/broadcom-radar");
    if (!directory || !directory.isDirectory()) { fail("SD directory unavailable"); return false; }
    // Enumerate names without opening each file: repeated exists() calls rescan FAT directories.
    while (true) {
        bool isDirectory = false;
        const auto path = directory.getNextFileName(&isDirectory);
        if (!path.length()) break;
        if (isDirectory) continue;
        const char* name = std::strrchr(path.c_str(), '/');
        name = name ? name + 1 : path.c_str();
        unsigned* sequence = nullptr;
        if (!std::strncmp(name, "scan-", 5)) { sequence = &sequence_; name += 5; }
        else if (!std::strncmp(name, "brcm-", 5)) { sequence = &detectionSequence_; name += 5; }
        else if (!std::strncmp(name, "test-", 5)) { sequence = &probeSequence_; name += 5; }
        if (!sequence) continue;
        unsigned value = 0, digits = 0;
        while (*name >= '0' && *name <= '9' && digits < 5) {
            value = value * 10 + (*name++ - '0'); ++digits;
        }
        if (digits < 3 || digits > 4 || !value || value > 9999) continue;
        bool recognized = false;
        for (const char* extension : {".json", ".csv", ".pcap", ".pcapng"}) {
            const size_t size = std::strlen(extension);
            if (!std::strncmp(name, extension, size) && (!name[size] || !std::strcmp(name + size, ".part"))) {
                recognized = true; break;
            }
        }
        if (recognized && value > *sequence) *sequence = value;
    }
    namesIndexed_ = true;
    return true;
}
bool Exporter::nextSequence() {
    if (!namesIndexed_ && !indexSequences()) return false;
    auto& sequence = probe_ ? probeSequence_ : detection_ ? detectionSequence_ : sequence_;
    // Never overwrite a prior export, including interrupted .part files.
    while (sequence < 9999) {
        ++sequence; bool exists = false; char path[80];
        for (const char* ext : {"json", "csv", "pcap", "pcapng"}) {
            for (bool partial : {false, true}) {
                filename(path, sizeof(path), ext, partial);
                if (SD.exists(path)) { exists = true; break; }
            }
            if (exists) break;
        }
        if (!exists) return true;
    }
    fail("Export names exhausted"); return false;
}
bool Exporter::needsDetection(const Observation& observation, const AccessPoint* aggregate, uint64_t nowUs) const {
    if (busy() || observation.malformed || nowUs < retryAfterUs_) return false;
    const auto& info = aggregate ? aggregate->info : observation;
    if (!info.evidence) return false;
    const uint8_t fields = identityFields(info.wps);
    for (size_t i = 0; i < savedCount_; ++i) if (!std::memcmp(saved_[i].bssid, info.bssid, 6))
        return (info.evidence & ~saved_[i].evidence) || (fields & ~saved_[i].fields);
    return true;
}
bool Exporter::saveDetection(const Observation& observation, const AccessPoint* aggregate, const Frame& frame,
                             const ScanStats& stats, const char* hardware, const Frame* companion) {
    if (!needsDetection(observation, aggregate, stats.nowUs)) return false;
    if (companion && !matchingAdvertisementContext(frame, *companion)) companion = nullptr;
    // Retry only on a later received advertisement, at most once every five seconds after an SD error.
    retryAfterUs_ = stats.nowUs + 5000000ULL;
    detection_ = true; probe_ = false;
    if (!available_ && !mount()) return false;
    if (!nextSequence()) return false;
    AccessPoint single;
    if (!aggregate) {
        single.info = observation; single.firstSeenUs = single.lastSeenUs = observation.seenUs;
        single.advertisements = single.completeAdvertisements = 1; single.maxRssi = observation.rssi;
        recordAdvertisementSource(single, observation);
        single.beacons = observation.subtype == 8; single.probeResponses = observation.subtype == 5;
        if (observation.captureChannel >= 1 && observation.captureChannel <= 14)
            single.captureChannels = 1 << (observation.captureChannel - 1);
        aggregate = &single;
    }
    const bool gps = frame.receiver.validAt(frame.timestampUs) || (companion && companion->receiver.validAt(companion->timestampUs));
    bool good = open("json");
    if (good) {
        FileSink sink(file_);
        good = writeDetectionJsonHeader(sink, stats, hardware, stats.country, companion != nullptr, gps) &&
               writeJsonAp(sink, *aggregate, true) && writeJsonFooter(sink) && sink.flush();
    }
    file_.flush(); good = good && file_.getWriteError() == 0; file_.close();
    if (good) good = open("csv");
    if (good) {
        FileSink sink(file_); good = writeCsvHeader(sink) && writeCsvAp(sink, *aggregate) && sink.flush();
    }
    file_.flush(); good = good && file_.getWriteError() == 0; file_.close();
    if (good) good = open("pcap");
    if (good) {
        FileSink sink(file_); good = writePcapHeader(sink) && (!companion || writePcapFrame(sink, *companion)) && writePcapFrame(sink, frame) && sink.flush();
    }
    file_.flush(); good = good && file_.getWriteError() == 0; file_.close();
    if (good && gps) {
        good = open("pcapng");
        if (good) {
            FileSink sink(file_); good = writePcapNgHeader(sink) && (!companion || writePcapNgFrame(sink, *companion)) && writePcapNgFrame(sink, frame) && sink.flush();
        }
        file_.flush(); good = good && file_.getWriteError() == 0; file_.close();
    }
    // Publish JSON last: all requested files, including a GPS sidecar, must be complete.
    if (!good || (gps && !publishFile("pcapng")) || !publishFile("pcap") || !publishFile("csv") || !publishFile("json")) {
        fail("BRCM save failed; retrying"); return false;
    }
    size_t index = 0;
    while (index < savedCount_ && std::memcmp(saved_[index].bssid, aggregate->info.bssid, 6)) ++index;
    if (index == savedCount_) {
        index = savedNext_; savedNext_ = (savedNext_ + 1) % kMaxAps;
        if (savedCount_ < kMaxAps) ++savedCount_;
        saved_[index] = SavedDetection{};
        std::memcpy(saved_[index].bssid, aggregate->info.bssid, 6);
    }
    saved_[index].evidence |= aggregate->info.evidence;
    saved_[index].fields |= identityFields(aggregate->info.wps);
    retryAfterUs_ = 0;
    std::snprintf(message_, sizeof(message_), "Saved brcm-%03u + PCAP", detectionSequence_);
    return true;
}
const char* Exporter::probeMessage(const WpsProbe& probe) const {
    return reportProbe_ == &probe && reportAttempt_ == probe.attemptId() ? reportMessage_ : "Report: pending";
}
bool Exporter::probeSaved(const WpsProbe& probe) const {
    return reportProbe_ == &probe && reportAttempt_ == probe.attemptId() && reportSaved_;
}
bool Exporter::saveProbe(const WpsProbe& probe, const char* hardware) {
    if (busy() || !probe.done()) return false;
    reportProbe_ = &probe; reportAttempt_ = probe.attemptId(); reportSaved_ = false;
    auto failed = [&]() {
        std::snprintf(reportMessage_, sizeof(reportMessage_), "%s", message_);
        return false;
    };
    probe_ = true; detection_ = false;
    if (!available_ && !mount()) return failed();
    if (!nextSequence()) return failed();
    bool good = open("json");
    if (good) { FileSink sink(file_); good = writeProbeJson(sink, probe, hardware) && sink.flush(); }
    file_.flush(); good = good && file_.getWriteError() == 0; file_.close();
    if (good) good = open("pcap");
    if (good) {
        FileSink sink(file_); good = writePcapHeader(sink);
        for (size_t i = 0; good && i < probe.recordCount(); ++i) good = writeProbePcapFrame(sink, probe.record(i));
        good = good && sink.flush();
    }
    file_.flush(); good = good && file_.getWriteError() == 0; file_.close();
    if (!good || !publishFile("pcap") || !publishFile("json")) { fail("Test save failed; kept part"); return failed(); }
    reportSaved_ = true;
    std::snprintf(message_, sizeof(message_), "Saved test-%03u + PCAP", probeSequence_);
    std::snprintf(reportMessage_, sizeof(reportMessage_), "Report: test-%03u saved", probeSequence_);
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
        else {
            good = sink.flush() && finishFile("pcap");
            phase_ = Phase::Finish;
            if (good && gps_) {
                good = open("pcapng");
                if (good) { FileSink pcapng(file_); good = writePcapNgHeader(pcapng) && pcapng.flush(); }
                phase_ = Phase::PcapNg; index_ = 0;
            }
        }
        break;
    case Phase::PcapNg:
        if (index_ < ring_->size()) good = writePcapNgFrame(sink, ring_->at(index_++));
        else { good = sink.flush() && finishFile("pcapng"); phase_ = Phase::Finish; }
        break;
    case Phase::Finish:
        phase_ = Phase::Idle;
        std::snprintf(message_, sizeof(message_), "Saved scan-%03u %s", sequence_, ring_->enabled() ? (gps_ ? "J/C/P/G" : "J/C/P") : "J/C; no P");
        return;
    default: return;
    }
    // A phase transition may have closed the file. All transition buffers were flushed above.
    if (good && (sink.flush() || phase_ == Phase::Finish)) return;
    fail("Save failed; parts kept");
}
}
