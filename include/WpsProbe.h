#pragma once
#include "RadarTypes.h"
namespace radar {
constexpr size_t kProbeRecords = 16, kProbeBytes = 512;
enum class ProbeStage { Idle, Requested, Advertisement, Authentication, Association, Identity, Start, Differential, Cleanup, Restore, Done };
enum class ProbeVerdict { Unknown, HostapdLike, BroadcomLike };
enum class ProbeResponse { None, FragmentAck, EapFailure, DeauthZero };
enum class ProbeReason { NotRun, Running, Response, NoWps, Timeout, ApRejected, UnexpectedEap, DriverRejected, Cancelled, InvalidAdvertisement, TraceFull, RadioSetupFailed, TransportReady };
struct ProbeTx {
    uint64_t timestampUs = 0;
    ProbeStage stage = ProbeStage::Idle;
    uint16_t length = 0;
    int error = 0, stockError = 0;
    bool compatibilityApplied = false, stockCheckObserved = false;
};
constexpr size_t kProbeTxEvents = 8;
struct ProbeRecord {
    uint64_t timestampUs = 0;
    uint16_t captured = 0, original = 0;
    bool tx = false;
    uint8_t bytes[kProbeBytes]{};
};
struct ProbeResult {
    ProbeStage stage = ProbeStage::Idle, stoppedAt = ProbeStage::Idle;
    ProbeVerdict verdict = ProbeVerdict::Unknown;
    ProbeReason reason = ProbeReason::NotRun;
    ProbeResponse response = ProbeResponse::None;
    uint64_t startedUs = 0, finishedUs = 0;
    int driverError = 0, cleanupError = 0;
    uint16_t txAccepted = 0, traceDropped = 0;
    ProbeTx tx[kProbeTxEvents]{};
    uint16_t txAttempts = 0;
    uint32_t advertisements = 0, malformed = 0, wrongSsid = 0, wrongChannel = 0, noWps = 0, stale = 0;
    uint64_t lastTargetUs = 0, scanRestoreUs = 0, scanRxFirstUs = 0;
    int8_t lastRssi = 0;
    uint16_t apStatus = 0;
    uint32_t scanRxFrames = 0, queueDrops = 0, oversizeDrops = 0;
    bool transportOnly = RADAR_TRANSPORT_ONLY, wscStartReceived = false, differentialSent = false, scanWasRunning = false;
    bool cleanupAccepted = false, restored = false, reported = false;
};
bool isProbeReply(const uint8_t* bytes, size_t length, const uint8_t* bssid, const uint8_t* station);
const char* probeStageName(ProbeStage stage);
const char* probeVerdictName(ProbeVerdict verdict);
const char* probeReasonName(ProbeReason reason);
const char* probeResponseName(ProbeResponse response);
class WpsProbe {
public:
    const char* startError(const Observation& target) const;
    bool request(const Observation& target);
    void begin(const uint8_t* station, uint64_t nowUs);
    void receive(const Frame& frame);
    void tick(uint64_t nowUs);
    bool pending(Frame& frame) const;
    bool matchesPending(const Frame& frame) const;
    void transmitted(int driverError, uint64_t nowUs, bool compatibilityApplied = false, int stockError = 0, bool stockCheckObserved = false);
    void cancel(uint64_t nowUs);
    void driverFailure(int error, uint64_t nowUs);
    void setupFailure(int error, uint64_t nowUs);
    void startRestoration(bool restored, bool running, uint64_t nowUs) {
        result_.restored = restored; result_.scanWasRunning = running;
        result_.scanRestoreUs = nowUs; result_.stage = ProbeStage::Restore;
    }
    void captureDrops(uint32_t queue, uint32_t oversize) { result_.queueDrops = queue; result_.oversizeDrops = oversize; }
    void completeReport(bool restored) { result_.restored = restored; result_.reported = true; result_.stage = ProbeStage::Done; }
    bool restoring() const { return result_.stage == ProbeStage::Restore; }
    bool requested() const { return result_.stage == ProbeStage::Requested; }
    bool busy() const { return result_.stage != ProbeStage::Idle && result_.stage != ProbeStage::Done; }
    bool done() const { return result_.stage == ProbeStage::Done; }
    const ProbeResult& result() const { return result_; }
    const Observation& target() const { return target_; }
    uint32_t attemptId() const { return attemptId_; }
    const uint8_t* station() const { return station_; }
    size_t recordCount() const { return recordCount_; }
    const ProbeRecord& record(size_t i) const { return records_[i]; }
private:
    void finish(ProbeReason reason, uint64_t nowUs, ProbeVerdict verdict = ProbeVerdict::Unknown);
    void record(const uint8_t* bytes, size_t length, uint64_t nowUs, bool tx);
    void header(uint8_t control, bool data = false);
    void authentication();
    void association();
    void eapolStart();
    void identity(uint8_t identifier);
    void differential(uint8_t identifier);
    void dataHeader(size_t eapLength);
    Observation target_;
    uint32_t attemptId_ = 0;
    ProbeResult result_;
    ProbeRecord records_[kProbeRecords]{};
    size_t recordCount_ = 0, pendingLength_ = 0, associationLength_ = 0;
    uint8_t station_[6]{}, pending_[kProbeBytes]{}, associationIes_[384]{};
    uint64_t deadlineUs_ = 0, lastTxUs_ = 0;
    uint16_t sequence_ = 0;
    uint8_t identifier_ = 0, identityReplies_ = 0;
    bool sessionStarted_ = false, wpsEntered_ = false, differentialSent_ = false, observedNoWps_ = false;
};
}
