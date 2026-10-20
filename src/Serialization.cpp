#include "Serialization.h"
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <initializer_list>
namespace radar {
namespace {
struct Writer {
    Sink& sink;
    bool ok = true;
    void raw(const char* s) { if (ok) ok = sink.write(reinterpret_cast<const uint8_t*>(s), std::strlen(s)); }
    void fmt(const char* format, ...) {
        char text[384]; va_list args; va_start(args, format);
        int n = std::vsnprintf(text, sizeof(text), format, args); va_end(args);
        if (n < 0 || size_t(n) >= sizeof(text)) { ok = false; return; }
        raw(text);
    }
    void quoted(const uint8_t* data, size_t length) {
        raw("\"");
        for (size_t i = 0; i < length; ++i) {
            uint8_t c = data[i];
            if (c == '"' || c == '\\') fmt("\\%c", c);
            else if (c < 32 || c > 126) fmt("\\u%04x", c);
            else { char s[2] = {char(c), 0}; raw(s); }
        }
        raw("\"");
    }
    void str(const char* value) { quoted(reinterpret_cast<const uint8_t*>(value), std::strlen(value)); }
    template<size_t N> void field(const char* name, const Bytes<N>& value) {
        str(name); raw(":"); quoted(value.data, value.length);
    }
    void hex(const uint8_t* value, size_t n) { raw("\""); for (size_t i = 0; i < n; ++i) fmt("%02x", value[i]); raw("\""); }
    void csv(const uint8_t* data, size_t n) {
        char text[257]; renderBytes(data, n, text, sizeof(text)); raw("\"");
        // Avoid spreadsheet formula execution when the CSV is opened interactively.
        if (text[0] == '=' || text[0] == '+' || text[0] == '-' || text[0] == '@') raw("'");
        for (const char* p = text; *p; ++p) { if (*p == '"') raw("\""); char s[2] = {*p, 0}; raw(s); }
        raw("\"");
    }
    void csv(const char* text) { csv(reinterpret_cast<const uint8_t*>(text), std::strlen(text)); }
};
void channels(Writer& w, uint16_t mask) {
    w.raw("["); bool first = true;
    for (unsigned i = 0; i < 14; ++i) if (mask & (1 << i)) { w.fmt("%s%u", first ? "" : ",", i + 1); first = false; }
    w.raw("]");
}
bool u32(Sink& sink, uint32_t value) {
    uint8_t bytes[4] = {uint8_t(value), uint8_t(value >> 8), uint8_t(value >> 16), uint8_t(value >> 24)};
    return sink.write(bytes, 4);
}
bool jsonHeader(Sink& sink, const ScanStats& s, const char* hardware, const char* country,
                bool pcapEnabled, size_t pcapFrames, uint32_t pcapOverwritten, bool detection) {
    Writer w{sink};
    w.raw("{\"schema_version\":1,\"firmware_version\":"); w.str(kFirmwareVersion);
    w.raw(",\"hardware\":"); w.str(hardware); w.raw(",\"mode\":\"passive-only\",\"country\":"); w.str(country);
    w.fmt(",\"started_us\":%llu,\"snapshot_us\":%llu,\"clock\":\"monotonic_since_boot\",\"dwell_ms\":%u,",
          (unsigned long long)s.startedUs, (unsigned long long)s.nowUs, kDwellMs);
    w.fmt("\"channel_mode\":\"%s\",\"selected_channel\":%u,\"received_frames\":%u,\"queue_drops\":%u,\"oversize_drops\":%u,",
          s.hopping ? "hopping" : "fixed", s.channel, s.received, s.queueDrops, s.oversizeDrops);
    w.fmt("\"rejected_frames\":%u,\"malformed_frames\":%u,\"store_dropped_observations\":%u,\"discarded_on_pause\":%u,",
          s.rejected, s.malformed, s.storeDrops, s.discardedOnPause);
    w.raw("\"listened_channels\":"); channels(w, s.listenedChannels);
    w.fmt(",\"store_replacements\":%u", s.storeReplacements);
    w.fmt(",\"pcap_enabled\":%s,\"pcap_frames\":%u,\"pcap_overwritten\":%u,", pcapEnabled ? "true" : "false", unsigned(pcapFrames), pcapOverwritten);
    if (detection) {
        w.raw("\"capture_reason\":\"broadcom_detection\",\"pcap_scope\":");
        w.str(pcapFrames == 2 ? "triggering_advertisement_with_companion" : "triggering_advertisement");
        w.fmt(",\"triggering_frame_index\":%u,", pcapFrames == 2 ? 1u : 0u);
    }
    w.raw("\"limits\":{\"max_aps\":128,\"queue_depth\":12,\"max_frame_bytes\":2304,\"wps_bytes_per_frame\":1024,\"wps_text_bytes\":64,\"vendor_summaries_per_ap\":8,\"pcap_depth\":16},");
    w.raw("\"limitations\":[\"Passive fingerprints do not establish vulnerability or safety\",\"2.4 GHz only; one channel at a time; advertisements can be missed\",\"Export pauses capture; full store can replace old NONE/WAIT records; protected records may fill all slots\",\"Malformed advertisements do not contribute identity or evidence\",\"OUI attribution is not implemented\",\"Binary strings use byte-wise JSON escapes; ssid_hex preserves exact bytes\",\"WPS text is bounded; vendor IEs are summaries, raw IEs require optional PCAP\",\"PCAP is a bounded recent snapshot with monotonic timestamps, without FCS or RadioTap\"],\"access_points\":[\n");
    return w.ok;
}
}
bool writeJsonHeader(Sink& sink, const ScanStats& s, const char* hardware, const char* country, const PcapRing& ring) {
    return jsonHeader(sink, s, hardware, country, ring.enabled(), ring.size(), ring.overwritten(), false);
}
bool writeDetectionJsonHeader(Sink& sink, const ScanStats& s, const char* hardware, const char* country, bool companion) {
    return jsonHeader(sink, s, hardware, country, true, companion ? 2 : 1, 0, true);
}
bool writeJsonAp(Sink& sink, const AccessPoint& ap, bool first) {
    Writer w{sink}; const auto& a = ap.info; char mac[18]; renderMac(a.bssid, mac, sizeof(mac));
    if (!first) w.raw(",\n");
    w.raw("{\"bssid\":"); w.str(mac); w.raw(","); w.field("ssid", a.ssid);
    w.raw(",\"ssid_hex\":"); w.hex(a.ssid.data, a.ssid.length);
    w.fmt(",\"ssid_hidden\":%s", hiddenSsid(a.ssid) ? "true" : "false");
    w.fmt(",\"ssid_present\":%s,\"rssi_dbm\":%d,\"max_rssi_dbm\":%d,\"channel\":%u,\"capabilities\":%u,",
          a.ssidPresent ? "true" : "false", a.rssi, ap.maxRssi, a.channel, a.capabilities);
    w.raw("\"status\":"); w.str(classificationName(classify(ap)));
    w.raw(",\"wps_advertised\":"); w.str(wpsStateName(wpsState(ap)));
    w.raw(",\"wps\":{"); w.field("manufacturer", a.wps.manufacturer); w.raw(","); w.field("model_name", a.wps.modelName);
    w.raw(","); w.field("model_number", a.wps.modelNumber); w.raw(","); w.field("device_name", a.wps.deviceName);
    w.raw(","); w.field("serial_number", a.wps.serialNumber); w.raw(",\"uuid_e\":"); w.hex(a.wps.uuidE.data, a.wps.uuidE.length);
    w.raw(",\"uuid_r\":"); w.hex(a.wps.uuidR.data, a.wps.uuidR.length);
    w.fmt(",\"identity_default_field_mask\":%u,\"truncated_text\":%s},\"evidence\":[", a.wps.defaults,
          (a.wps.manufacturer.truncated || a.wps.modelName.truncated || a.wps.modelNumber.truncated || a.wps.deviceName.truncated || a.wps.serialNumber.truncated) ? "true" : "false");
    bool evidenceFirst = true;
    for (uint8_t bit = 1; bit <= 4; bit <<= 1) if (a.evidence & bit) {
        if (!evidenceFirst) w.raw(",");
        evidenceFirst = false;
        w.raw("{\"name\":"); w.str(evidenceName(bit)); w.raw(",\"source\":"); w.str(evidenceSource(bit)); w.raw("}");
    }
    w.fmt("],\"first_seen_us\":%llu,\"last_seen_us\":%llu,\"advertisements\":%u,\"complete_advertisements\":%u,\"malformed_advertisements\":%u,\"beacons\":%u,\"probe_responses\":%u,",
          (unsigned long long)ap.firstSeenUs, (unsigned long long)ap.lastSeenUs, ap.advertisements, ap.completeAdvertisements, ap.malformedAdvertisements, ap.beacons, ap.probeResponses);
    w.raw("\"capture_channels\":"); channels(w, ap.captureChannels);
    w.raw(",\"ie_ids\":["); bool idFirst = true;
    for (unsigned i = 0; i < 256; ++i) if (a.ieIds[i >> 3] & (1 << (i & 7))) { w.fmt("%s%u", idFirst ? "" : ",", i); idFirst = false; }
    w.raw("],\"vendor_ies\":[");
    for (unsigned i = 0; i < a.vendorCount; ++i) {
        if (i) w.raw(",");
        w.raw("{\"prefix_hex\":"); w.hex(a.vendors[i].prefix, a.vendors[i].length < 4 ? a.vendors[i].length : 4);
        w.fmt(",\"payload_length\":%u}", a.vendors[i].length);
    }
    w.fmt("],\"vendor_summary_overflow\":%s}", a.vendorOverflow ? "true" : "false");
    return w.ok;
}
bool writeJsonFooter(Sink& sink) { Writer w{sink}; w.raw("\n]}\n"); return w.ok; }
bool writeCsvHeader(Sink& sink) {
    Writer w{sink}; w.raw("bssid,ssid,ssid_hex,rssi_dbm,max_rssi_dbm,channel,capabilities,manufacturer,model_name,model_number,device_name,serial_number,uuid_e,uuid_r,wps_advertised,status,evidence,first_seen_us,last_seen_us,advertisements,complete_advertisements,malformed_advertisements\r\n"); return w.ok;
}
bool writeCsvAp(Sink& sink, const AccessPoint& ap) {
    Writer w{sink}; const auto& a = ap.info; char mac[18]; renderMac(a.bssid, mac, sizeof(mac));
    w.csv(mac); w.raw(","); w.csv(a.ssid.data, a.ssid.length); w.raw(","); w.hex(a.ssid.data, a.ssid.length);
    w.fmt(",%d,%d,%u,%u,", a.rssi, ap.maxRssi, a.channel, a.capabilities);
    for (const Text* field : {&a.wps.manufacturer, &a.wps.modelName, &a.wps.modelNumber, &a.wps.deviceName, &a.wps.serialNumber}) {
        w.csv(field->data, field->length); w.raw(",");
    }
    w.hex(a.wps.uuidE.data, a.wps.uuidE.length); w.raw(","); w.hex(a.wps.uuidR.data, a.wps.uuidR.length); w.raw(",");
    w.csv(wpsStateName(wpsState(ap))); w.raw(","); w.csv(classificationName(classify(ap))); w.raw(",\"");
    bool first = true;
    for (uint8_t bit = 1; bit <= 4; bit <<= 1) if (a.evidence & bit) { if (!first) w.raw(";"); first = false; w.raw(evidenceName(bit)); }
    w.fmt("\",%llu,%llu,%u,%u,%u\r\n", (unsigned long long)ap.firstSeenUs, (unsigned long long)ap.lastSeenUs,
          ap.advertisements, ap.completeAdvertisements, ap.malformedAdvertisements);
    return w.ok;
}
bool writePcapHeader(Sink& s) {
    const uint8_t prefix[] = {0xd4,0xc3,0xb2,0xa1,2,0,4,0};
    return s.write(prefix, sizeof(prefix)) && u32(s, 0) && u32(s, 0) && u32(s, kMaxFrame) && u32(s, 105);
}
bool writePcapFrame(Sink& s, const Frame& f) {
    if (!isAdvertisement(f.bytes, f.length) || f.length < 36 || f.length > kMaxFrame) return false;
    return u32(s, f.timestampUs / 1000000ULL) && u32(s, f.timestampUs % 1000000ULL) &&
           u32(s, f.length) && u32(s, f.length) && s.write(f.bytes, f.length);
}
bool writeProbePcapFrame(Sink& s, const ProbeRecord& r) {
    if (!r.captured || r.captured > kProbeBytes || r.captured > r.original || r.original > kMaxFrame) return false;
    return u32(s, r.timestampUs / 1000000ULL) && u32(s, r.timestampUs % 1000000ULL) &&
           u32(s, r.captured) && u32(s, r.original) && s.write(r.bytes, r.captured);
}
bool writeProbeJson(Sink& sink, const WpsProbe& probe, const char* hardware) {
    Writer w{sink}; const auto& r = probe.result(); char bssid[18], station[18];
    renderMac(probe.target().bssid, bssid, sizeof(bssid)); renderMac(probe.station(), station, sizeof(station));
    w.raw("{\"schema_version\":2,\"firmware_version\":"); w.str(kFirmwareVersion);
    w.raw(",\"hardware\":"); w.str(hardware); w.raw(",\"mode\":");
    w.str(r.transportOnly ? "experimental-wps-transport" : "experimental-active-wps");
    w.raw(",\"driver_transport\":"); w.str(RADAR_DRIVER_COMPAT ? "scoped-idf447-compatibility" : "stock-public-api");
    w.raw(",\"bssid\":"); w.str(bssid);
    w.raw(",\"station\":"); w.str(station); w.raw(","); w.field("ssid", probe.target().ssid);
    w.fmt(",\"channel\":%u,\"started_us\":%llu,\"finished_us\":%llu,\"clock\":\"monotonic_since_boot\",",
          probe.target().channel, (unsigned long long)r.startedUs, (unsigned long long)r.finishedUs);
    w.raw("\"implementation_candidate\":"); w.str(probeVerdictName(r.verdict)); w.raw(",\"reason\":"); w.str(probeReasonName(r.reason));
    w.raw(",\"stopped_at\":"); w.str(probeStageName(r.stoppedAt));
    w.raw(",\"differential_response\":"); w.str(probeResponseName(r.response));
    w.fmt(",\"differential_sent\":%s", r.differentialSent ? "true" : "false");
    w.raw(",\"driver_error_name\":");
    w.str(r.driverError == 0 ? "ESP_OK" : r.driverError == 0x102 ? "ESP_ERR_INVALID_ARG" : "SEE_NUMERIC_ERROR_CODE");
    w.fmt(",\"driver_error\":%d,\"tx_accepted_by_driver\":%u,\"cleanup_accepted_by_driver\":%s,\"cleanup_error\":%d,",
          r.driverError, r.txAccepted, r.cleanupAccepted ? "true" : "false", r.cleanupError);
    w.fmt("\"pcap_frames\":%u,\"trace_dropped\":%u,\"trace_limit\":%u,\"captured_bytes_per_frame\":%u,",
          unsigned(probe.recordCount()), r.traceDropped, unsigned(kProbeRecords), unsigned(kProbeBytes));
    w.fmt("\"transport_only\":%s,\"wsc_start_received\":%s,\"hardware_calibrated\":false,\"continuation_fragments_sent\":false,\"declared_wps_message_length\":%s,",
          r.transportOnly ? "true" : "false", r.wscStartReceived ? "true" : "false", r.transportOnly ? "null" : "0");
    w.fmt("\"revalidation\":{\"window_ms\":10000,\"advertisements\":%u,\"malformed\":%u,\"wrong_ssid\":%u,\"wrong_channel\":%u,\"no_wps\":%u,\"stale\":%u,",
          r.advertisements, r.malformed, r.wrongSsid, r.wrongChannel, r.noWps, r.stale);
    w.fmt("\"last_target_us\":%llu,\"last_rssi_dbm\":%d,\"rssi_observed\":%s},\"ap_status_or_reason\":%u,",
          (unsigned long long)r.lastTargetUs, r.lastRssi, r.lastTargetUs ? "true" : "false", r.apStatus);
    w.fmt("\"capture_queue_drops\":%u,\"capture_oversize_drops\":%u,\"scan_restored\":%s,\"scan_was_running\":%s,\"scan_rx_frames\":%u,\"scan_rx_first_us\":%llu,",
          r.queueDrops, r.oversizeDrops, r.restored ? "true" : "false", r.scanWasRunning ? "true" : "false", r.scanRxFrames, (unsigned long long)r.scanRxFirstUs);
    w.raw("\"claim_boundary\":\"Experimental transport or implementation-family candidate; not proof of hostapd, vulnerability or patch status. Driver acceptance is not over-the-air proof. Scan RX counts advertisements observed after restoring capture.\",\"tx_attempts\":[");
    for (size_t i = 0; i < r.txAttempts; ++i) {
        const auto& tx = r.tx[i]; w.raw(i ? ",{\"stage\":" : "{\"stage\":"); w.str(probeStageName(tx.stage));
        w.fmt(",\"timestamp_us\":%llu,\"length\":%u,\"driver_error\":%d,\"stock_check_error\":",
              (unsigned long long)tx.timestampUs, tx.length, tx.error);
        if (tx.stockCheckObserved) w.fmt("%d", tx.stockError); else w.raw("null");
        w.fmt(",\"compatibility_applied\":%s}", tx.compatibilityApplied ? "true" : "false");
    }
    w.raw("],\"records\":[");
    for (size_t i = 0; i < probe.recordCount(); ++i) {
        const auto& record = probe.record(i);
        w.fmt("%s{\"pcap_index\":%u,\"direction\":\"%s\",\"captured\":%u,\"original\":%u}", i ? "," : "", unsigned(i),
              record.tx ? "TX_DRIVER_ACCEPTED" : "RX", record.captured, record.original);
    }
    w.raw("]}\n"); return w.ok;
}
}
