#include "WpsProbe.h"
#include "Parsers.h"
#include <cstring>
namespace radar {
namespace {
constexpr uint8_t kSnap[] = {0xaa,0xaa,3,0,0,0,0x88,0x8e};
constexpr uint8_t kWsc[] = {0xfe,0,0x37,0x2a,0,0,0,1};
constexpr uint8_t kAssociationWps[] = {221,14,0,0x50,0xf2,4,0x10,0x4a,0,1,0x10,0x10,0x3a,0,1,1};
constexpr char kIdentity[] = "WFA-SimpleConfig-Enrollee-1-0";
uint16_t be16(const uint8_t* p) { return uint16_t(p[0]) << 8 | p[1]; }
uint16_t le16(const uint8_t* p) { return uint16_t(p[1]) << 8 | p[0]; }
void putBe16(uint8_t* p, size_t v) { p[0] = v >> 8; p[1] = v; }
bool equal(const uint8_t* a, const uint8_t* b) { return !std::memcmp(a, b, 6); }
}
bool isProbeReply(const uint8_t* p, size_t n, const uint8_t* bssid, const uint8_t* station) {
    if (n < 24 || (p[0] & 3) || (p[1] & 0xc4) || (p[22] & 15) || !equal(p + 10, bssid)) return false;
    if ((p[0] & 0x0c) == 0) {
        if ((p[1] & 3) || !equal(p + 16, bssid)) return false;
        if (p[0] == 0x80 || p[0] == 0x50) {
            constexpr uint8_t broadcast[6] = {255,255,255,255,255,255};
            return n >= 36 && (equal(p + 4, station) || equal(p + 4, broadcast));
        }
        return equal(p + 4, station) && (p[0] == 0xb0 || p[0] == 0x10 || p[0] == 0xa0 || p[0] == 0xc0);
    }
    if ((p[0] != 0x08 && p[0] != 0x88) || (p[1] & 3) != 2 || !equal(p + 4, station)) return false;
    const size_t header = p[0] == 0x88 ? 26 : 24;
    return n >= header + 12 && !std::memcmp(p + header, kSnap, sizeof(kSnap)) && p[header + 9] == 0;
}
const char* probeStageName(ProbeStage stage) {
    switch (stage) {
    case ProbeStage::Idle: return "NOT_RUN";
    case ProbeStage::Requested: return "REQUESTED";
    case ProbeStage::Advertisement: return "REVALIDATE";
    case ProbeStage::Authentication: return "AUTHENTICATION";
    case ProbeStage::Association: return "ASSOCIATION";
    case ProbeStage::Identity: return "EAP_IDENTITY";
    case ProbeStage::Start: return "WSC_START";
    case ProbeStage::Differential: return "WPS_DIFFERENTIAL";
    case ProbeStage::Cleanup: return "CLEANUP";
    case ProbeStage::Restore: return "CHECK_SCAN_RX";
    default: return "DONE";
    }
}
const char* probeVerdictName(ProbeVerdict verdict) {
    return verdict == ProbeVerdict::HostapdLike ? "HOSTAPD_LIKE" : verdict == ProbeVerdict::BroadcomLike ? "BRCM_WPS_LIKE" : "UNKNOWN";
}
const char* probeResponseName(ProbeResponse response) {
    switch (response) {
    case ProbeResponse::FragmentAck: return "WSC_FRAGMENT_ACK";
    case ProbeResponse::EapFailure: return "EAP_FAILURE";
    case ProbeResponse::DeauthZero: return "DEAUTH_REASON_ZERO";
    default: return "NOT_OBSERVED";
    }
}
const char* probeReasonName(ProbeReason reason) {
    switch (reason) {
    case ProbeReason::NotRun: return "NOT_RUN";
    case ProbeReason::Running: return "RUNNING";
    case ProbeReason::Response: return "EXPLICIT_RESPONSE_UNCALIBRATED";
    case ProbeReason::NoWps: return "WPS_NOT_ADVERTISED";
    case ProbeReason::Timeout: return "TIMEOUT";
    case ProbeReason::ApRejected: return "AP_REJECTED_SESSION";
    case ProbeReason::UnexpectedEap: return "UNEXPECTED_EAP";
    case ProbeReason::DriverRejected: return "DRIVER_REJECTED_TX";
    case ProbeReason::Cancelled: return "CANCELLED";
    case ProbeReason::TraceFull: return "TRACE_FULL";
    case ProbeReason::RadioSetupFailed: return "RADIO_SETUP_FAILED";
    case ProbeReason::TransportReady: return "TRANSPORT_REACHED_WSC_START";
    default: return "INVALID_ADVERTISEMENT";
    }
}
const char* WpsProbe::startError(const Observation& target) const {
    if (busy()) return "Another test is running";
    return wpsTargetError(target);
}
bool WpsProbe::request(const Observation& target) {
    if (startError(target)) return false;
    if (!++attemptId_) ++attemptId_;
    target_ = target; result_ = ProbeResult{}; result_.stage = ProbeStage::Requested; result_.reason = ProbeReason::Running;
    result_.stationRotationRequested = randomStation_;
    recordCount_ = pendingLength_ = associationLength_ = 0;
    lastTxUs_ = 0;
    sequence_ = 0; identityReplies_ = 0; sessionStarted_ = wpsEntered_ = differentialSent_ = observedNoWps_ = false;
    std::memset(station_, 0, sizeof(station_));
    return true;
}
void WpsProbe::begin(const uint8_t* station, uint64_t nowUs) {
    if (!requested()) return;
    std::memcpy(station_, station, 6); result_.startedUs = nowUs;
    result_.stage = ProbeStage::Advertisement; deadlineUs_ = nowUs + 10000000ULL;
}
void WpsProbe::record(const uint8_t* p, size_t n, uint64_t nowUs, bool tx) {
    if (recordCount_ == kProbeRecords) { ++result_.traceDropped; return; }
    auto& r = records_[recordCount_++]; r.timestampUs = nowUs; r.tx = tx; r.original = n;
    r.captured = n < kProbeBytes ? n : kProbeBytes; std::memcpy(r.bytes, p, r.captured);
}
void WpsProbe::header(uint8_t control, bool data) {
    std::memset(pending_, 0, 24); pending_[0] = control; pending_[1] = data ? 1 : 0;
    std::memcpy(pending_ + 4, target_.bssid, 6); std::memcpy(pending_ + 10, station_, 6);
    std::memcpy(pending_ + 16, target_.bssid, 6);
    const uint16_t seq = (sequence_++ & 0xfff) << 4; pending_[22] = seq; pending_[23] = seq >> 8;
    pendingLength_ = 24;
}
void WpsProbe::authentication() {
    header(0xb0); std::memset(pending_ + 24, 0, 6); pending_[26] = 1; pendingLength_ = 30;
    result_.stage = ProbeStage::Authentication;
}
void WpsProbe::association() {
    header(0);
    const uint16_t capabilities = 1 | (target_.capabilities & (0x10 | 0x20 | 0x400));
    pending_[24] = capabilities; pending_[25] = capabilities >> 8; pending_[26] = 10; pending_[27] = 0;
    std::memcpy(pending_ + 28, associationIes_, associationLength_);
    std::memcpy(pending_ + 28 + associationLength_, kAssociationWps, sizeof(kAssociationWps));
    pendingLength_ = 28 + associationLength_ + sizeof(kAssociationWps); result_.stage = ProbeStage::Association;
}
void WpsProbe::dataHeader(size_t eapLength) {
    header(0x08, true); std::memcpy(pending_ + 24, kSnap, sizeof(kSnap));
    pending_[32] = 1; pending_[33] = 0; putBe16(pending_ + 34, eapLength);
    pendingLength_ = 36 + eapLength;
}
void WpsProbe::eapolStart() {
    dataHeader(0); pending_[32] = 2; pending_[33] = 1; result_.stage = ProbeStage::Identity;
}
void WpsProbe::identity(uint8_t id) {
    constexpr size_t n = 5 + sizeof(kIdentity) - 1;
    dataHeader(n); pending_[36] = 2; pending_[37] = id; putBe16(pending_ + 38, n); pending_[40] = 1;
    std::memcpy(pending_ + 41, kIdentity, sizeof(kIdentity) - 1); result_.stage = ProbeStage::Start;
}
void WpsProbe::differential(uint8_t id) {
    dataHeader(16); pending_[36] = 2; pending_[37] = id; putBe16(pending_ + 38, 16);
    std::memcpy(pending_ + 40, kWsc, sizeof(kWsc));
    pending_[48] = 4; pending_[49] = 3; pending_[50] = pending_[51] = 0;
    identifier_ = id; result_.stage = ProbeStage::Differential;
}
bool WpsProbe::pending(Frame& frame) const {
    if (!pendingLength_) return false;
    frame.length = pendingLength_; frame.channel = target_.channel;
    std::memcpy(frame.bytes, pending_, pendingLength_); return true;
}
bool WpsProbe::matchesPending(const Frame& frame) const {
    return pendingLength_ && frame.channel == target_.channel && frame.length == pendingLength_ &&
           !std::memcmp(frame.bytes, pending_, pendingLength_);
}
void WpsProbe::transmitted(int error, uint64_t nowUs, bool compatibilityApplied, int stockError, bool stockCheckObserved) {
    if (!pendingLength_) return;
    if (result_.txAttempts < kProbeTxEvents) {
        auto& tx = result_.tx[result_.txAttempts++]; tx.timestampUs = nowUs; tx.stage = result_.stage;
        tx.length = pendingLength_; tx.error = error; tx.stockError = stockError; tx.compatibilityApplied = compatibilityApplied;
        tx.stockCheckObserved = stockCheckObserved;
    }
    const bool cleanup = result_.stage == ProbeStage::Cleanup;
    if (!error) { record(pending_, pendingLength_, nowUs, true); ++result_.txAccepted; lastTxUs_ = nowUs; }
    pendingLength_ = 0;
    if (cleanup) {
        result_.cleanupAccepted = !error; result_.cleanupError = error;
        result_.stage = ProbeStage::Done; result_.finishedUs = nowUs; return;
    }
    if (error) { driverFailure(error, nowUs); return; }
    if (result_.stage == ProbeStage::Authentication) sessionStarted_ = true;
    if (result_.stage == ProbeStage::Differential) differentialSent_ = result_.differentialSent = true;
    deadlineUs_ = nowUs + 3000000ULL;
}
void WpsProbe::finish(ProbeReason reason, uint64_t nowUs, ProbeVerdict verdict) {
    if (done() || result_.stage == ProbeStage::Idle) return;
    result_.stoppedAt = result_.stage; result_.reason = reason; result_.verdict = verdict;
    if ((reason == ProbeReason::Response || reason == ProbeReason::TransportReady) && result_.traceDropped) {
        result_.reason = ProbeReason::TraceFull; result_.verdict = ProbeVerdict::Unknown;
    }
    pendingLength_ = 0;
    if (sessionStarted_) {
        header(0xc0); pending_[24] = 3; pending_[25] = 0; pendingLength_ = 26;
        result_.stage = ProbeStage::Cleanup;
    } else { result_.stage = ProbeStage::Done; result_.finishedUs = nowUs; }
}
void WpsProbe::driverFailure(int error, uint64_t nowUs) { result_.driverError = error; finish(ProbeReason::DriverRejected, nowUs); }
void WpsProbe::setupFailure(int error, uint64_t nowUs) { result_.driverError = error; finish(ProbeReason::RadioSetupFailed, nowUs); }
void WpsProbe::cancel(uint64_t nowUs) { if (!restoring()) finish(ProbeReason::Cancelled, nowUs); }
void WpsProbe::tick(uint64_t nowUs) {
    if (busy() && !requested() && !restoring() && result_.stage != ProbeStage::Cleanup &&
        (nowUs >= deadlineUs_ || nowUs - result_.startedUs >= 25000000ULL))
        finish(result_.stage == ProbeStage::Advertisement && observedNoWps_ ? ProbeReason::NoWps : ProbeReason::Timeout, nowUs);
}
void WpsProbe::receive(const Frame& frame) {
    if (restoring()) {
        if (frame.timestampUs >= result_.scanRestoreUs && isAdvertisement(frame.bytes, frame.length)) {
            ++result_.scanRxFrames; if (!result_.scanRxFirstUs) result_.scanRxFirstUs = frame.timestampUs;
        }
        return;
    }
    if (!busy() || requested() || pendingLength_ ||
        !isProbeReply(frame.bytes, frame.length, target_.bssid, station_)) return;
    if (frame.timestampUs < result_.startedUs || frame.timestampUs < lastTxUs_) { ++result_.stale; return; }
    result_.lastTargetUs = frame.timestampUs; result_.lastRssi = frame.rssi;
    if (frame.channel != target_.channel) { ++result_.wrongChannel; return; }
    const auto* p = frame.bytes; const size_t n = frame.length;
    if (result_.stage == ProbeStage::Advertisement) {
        if (p[0] != 0x80 && p[0] != 0x50) return;
        ++result_.advertisements;
        if (result_.advertisements == 1) record(p, n, frame.timestampUs, false);
        Observation fresh;
        if (!parser_.parse(p, n, frame.rssi, frame.channel, frame.timestampUs, fresh) || fresh.malformed) { ++result_.malformed; return; }
        if (fresh.channel != target_.channel) { ++result_.wrongChannel; return; }
        if (fresh.ssid.length != target_.ssid.length || std::memcmp(fresh.ssid.data, target_.ssid.data, fresh.ssid.length)) { ++result_.wrongSsid; return; }
        if (!fresh.wpsAdvertised) { observedNoWps_ = true; ++result_.noWps; return; }
        target_.capabilities = fresh.capabilities;
        associationLength_ = 0; bool rates = false;
        for (size_t i = 36; i + 2 <= n;) {
            const size_t length = size_t(p[i + 1]) + 2;
            if (length > n - i) { finish(ProbeReason::InvalidAdvertisement, frame.timestampUs); return; }
            const bool wpa = p[i] == 221 && length >= 6 && !std::memcmp(p + i + 2, "\x00\x50\xf2\x01", 4);
            if (p[i] == 0 || p[i] == 1 || p[i] == 50 || p[i] == 48 || wpa) {
                if (length > sizeof(associationIes_) - associationLength_) { finish(ProbeReason::InvalidAdvertisement, frame.timestampUs); return; }
                std::memcpy(associationIes_ + associationLength_, p + i, length); associationLength_ += length;
                rates |= p[i] == 1 && length > 2;
            }
            i += length;
        }
        if (!rates) {
            constexpr uint8_t fallback[] = {1,8,0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24};
            if (sizeof(fallback) > sizeof(associationIes_) - associationLength_) { finish(ProbeReason::InvalidAdvertisement, frame.timestampUs); return; }
            std::memcpy(associationIes_ + associationLength_, fallback, sizeof(fallback)); associationLength_ += sizeof(fallback);
        }
        if (result_.advertisements != 1) record(p, n, frame.timestampUs, false);
        authentication(); return;
    }
    if (p[0] == 0x80 || p[0] == 0x50) return;
    record(p, n, frame.timestampUs, false);
    if ((p[0] == 0xc0 || p[0] == 0xa0) && n >= 26) {
        result_.apStatus = le16(p + 24);
        sessionStarted_ = false;
        if (p[0] == 0xc0 && result_.apStatus == 0 && result_.stage == ProbeStage::Differential && wpsEntered_ && differentialSent_) {
            result_.response = ProbeResponse::DeauthZero;
            finish(ProbeReason::Response, frame.timestampUs, ProbeVerdict::BroadcomLike);
        } else finish(ProbeReason::ApRejected, frame.timestampUs);
        return;
    }
    if (result_.stage == ProbeStage::Authentication) {
        if (p[0] != 0xb0 || n < 30 || le16(p + 24) != 0 || le16(p + 26) != 2) return;
        if ((result_.apStatus = le16(p + 28))) finish(ProbeReason::ApRejected, frame.timestampUs);
        else association();
        return;
    }
    if (result_.stage == ProbeStage::Association) {
        if (p[0] != 0x10 || n < 30) return;
        if ((result_.apStatus = le16(p + 26))) finish(ProbeReason::ApRejected, frame.timestampUs);
        else eapolStart();
        return;
    }
    if (p[0] != 0x08 && p[0] != 0x88) return;
    const size_t offset = p[0] == 0x88 ? 34 : 32;
    if (n < offset + 8) return;
    const size_t eapolLength = be16(p + offset + 2);
    if (eapolLength > n - offset - 4 || eapolLength < 4) return;
    const uint8_t* eap = p + offset + 4; const size_t length = be16(eap + 2);
    if (length != eapolLength) return;
    if ((result_.stage == ProbeStage::Identity || result_.stage == ProbeStage::Start) && eap[0] == 1 && length >= 5 && eap[4] == 1) {
        if (++identityReplies_ <= 3) identity(eap[1]);
        else finish(ProbeReason::UnexpectedEap, frame.timestampUs);
        return;
    }
    const bool wsc = length >= 14 && !std::memcmp(eap + 4, kWsc, sizeof(kWsc));
    if (result_.stage == ProbeStage::Start && eap[0] == 1 && wsc && length == 14 && eap[12] == 1 && eap[13] == 0) {
        wpsEntered_ = result_.wscStartReceived = true;
        if (result_.transportOnly) finish(ProbeReason::TransportReady, frame.timestampUs);
        else differential(eap[1]);
        return;
    }
    if (result_.stage == ProbeStage::Differential && wpsEntered_ && differentialSent_) {
        // A retry of the WSC Start already answered by our single fragment is not a differential response.
        if (eap[0] == 1 && wsc && length == 14 && eap[1] == identifier_ && eap[12] == 1 && eap[13] == 0) return;
        if (eap[0] == 4 && length == 4 && eap[1] == identifier_) {
            result_.response = ProbeResponse::EapFailure;
            finish(ProbeReason::Response, frame.timestampUs, ProbeVerdict::BroadcomLike);
        } else if (eap[0] == 1 && wsc && length == 14 && eap[12] == 6 && eap[13] == 0) {
            result_.response = ProbeResponse::FragmentAck;
            finish(ProbeReason::Response, frame.timestampUs, ProbeVerdict::HostapdLike);
        } else finish(ProbeReason::UnexpectedEap, frame.timestampUs);
        return;
    }
    finish(ProbeReason::UnexpectedEap, frame.timestampUs);
}
}
