#!/usr/bin/env python3
"""Independently read real Exporter output using JSON, CSV and PCAP decoders."""
import csv
import json
import pathlib
import struct
import sys

root = pathlib.Path(sys.argv[1])
report = json.loads((root / "scan-001.json").read_text())
assert report["mode"] == "passive-only" and report["schema_version"] == 1
assert report["listened_channels"] == list(range(1, 14))
aps = report["access_points"]
assert len(aps) == 3 and len({ap["bssid"] for ap in aps}) == 3
assert aps[0]["status"] == "BROADCOM_SIGNATURE"
assert aps[1]["wps"]["uuid_r"] == "000102030405060708090a0b0c0d0ebb"
assert {item["name"] for item in aps[0]["evidence"]} == {"broadcom_proprietary_ie"}
assert not report["gps_pcapng_sidecar"] and all(ap["receiver_position"] is None for ap in aps)
assert aps[0]["metadata_sources"] == 1
assert aps[0]["evidence"][0]["contributing_frame_types"] == ["beacon"]
assert aps[0]["wps"]["manufacturer"] == "Example Vendor"
assert aps[0]["ssid_hex"] == "00ff222c0a" and aps[0]["ssid"] == '\x00\xff",\n'
assert aps[2]["ssid_hex"] == "3d312b31"
rows = list(csv.DictReader((root / "scan-001.csv").open(newline="")))
assert len(rows) == 3 and all(None not in row for row in rows)
assert rows[2]["ssid"] == "'=1+1"
assert rows[1]["uuid_r"] == aps[1]["wps"]["uuid_r"]

data = (root / "scan-001.pcap").read_bytes()
magic, major, minor, zone, sigfigs, snaplen, dlt = struct.unpack_from("<IHHIIII", data)
assert (magic, major, minor, snaplen, dlt) == (0xA1B2C3D4, 2, 4, 2304, 105)
offset = 24
count = 0
while offset < len(data):
    seconds, micros, captured, original = struct.unpack_from("<IIII", data, offset)
    offset += 16
    assert seconds == 2 and 0 <= micros < 1_000_000
    assert 36 <= captured == original <= snaplen
    frame = data[offset:offset + captured]
    assert len(frame) == captured and frame[0] in (0x80, 0x50)
    assert frame[36:38] == b"\x00\x05"  # SSID is binary and preserved in PCAP.
    offset += captured
    count += 1
assert offset == len(data) and count == 16
print("PASS: JSON/CSV round trip and 16 raw 802.11 PCAP records, DLT 105")

report = json.loads((root / "brcm-001.json").read_text())
assert report["capture_reason"] == "broadcom_detection"
assert report["pcap_scope"] == "triggering_advertisement"
assert report["pcap_enabled"] and report["pcap_frames"] == 1
assert len(report["access_points"]) == 1
ap = report["access_points"][0]
assert ap["status"] == "BROADCOM_SIGNATURE" and ap["ssid"] == "Test"
rows = list(csv.DictReader((root / "brcm-001.csv").open(newline="")))
assert len(rows) == 1 and rows[0]["bssid"] == ap["bssid"]
data = (root / "brcm-001.pcap").read_bytes()
assert struct.unpack_from("<IHHIIII", data) == (0xA1B2C3D4, 2, 4, 0, 0, 2304, 105)
seconds, micros, captured, original = struct.unpack_from("<IIII", data, 24)
assert seconds == 2 and micros == 0 and captured == original == len(data) - 40
frame = data[40:]
assert frame[16:22].hex() == ap["bssid"].replace(":", "").lower()
assert b"\xdd\x09\x00\x10\x18\x02" in frame
print("PASS: automatic BRCM JSON/CSV and matching single-frame PCAP with manual capture disabled")

context = json.loads((root / "context-001.json").read_text())
assert context["pcap_frames"] == 2 and context["triggering_frame_index"] == 1
assert context["pcap_scope"] == "triggering_advertisement_with_companion"
data = (root / "context-001.pcap").read_bytes()
offset = 24
for subtype, timestamp in [(0x50, 1), (0x80, 2)]:
    seconds, micros, captured, original = struct.unpack_from("<IIII", data, offset)
    offset += 16
    assert seconds == timestamp and micros == 0 and captured == original
    frame = data[offset:offset + captured]
    assert frame[0] == subtype
    assert frame[16:22].hex() == context["access_points"][0]["bssid"].replace(":", "").lower()
    offset += captured
assert offset == len(data)
print("PASS: paired same-BSSID Probe Response/Beacon PCAP, capture order and triggering frame index")

# Independently decode optional GPS output, including block boundaries and options.
for prefix, expected_count in [("gps-scan-001", 2), ("gps-detection-001", 1)]:
    report = json.loads((root / (prefix + ".json")).read_text())
    assert report["gps_pcapng_sidecar"] and report["position_scope"] == "receiver_position_at_observation"
    position = report["access_points"][0]["receiver_position"]
    assert abs(position["latitude"] - 48.1173) < 1e-7 and abs(position["longitude"] - 11.5166666) < 1e-7
    assert position["fix_utc"] == "1994-03-23T12:35:19Z" and position["fix_age_ms"] == 100
    rows = list(csv.DictReader((root / (prefix + ".csv")).open(newline="")))
    assert len(rows) == 1 and None not in rows[0]
    assert rows[0]["position_scope"] == report["position_scope"]
    assert float(rows[0]["receiver_longitude"]) == position["longitude"]
    classic = (root / (prefix + ".pcap")).read_bytes()
    classic_frames = []
    offset = 24
    while offset < len(classic):
        seconds, micros, captured, original = struct.unpack_from("<IIII", classic, offset)
        offset += 16
        classic_frames.append((seconds * 1_000_000 + micros, classic[offset:offset+captured]))
        assert captured == original
        offset += captured
    data = (root / (prefix + ".pcapng")).read_bytes()
    offset = 0
    blocks = []
    tagged = []
    while offset < len(data):
        kind, size = struct.unpack_from("<II", data, offset)
        assert size >= 12 and size % 4 == 0 and offset + size <= len(data)
        assert struct.unpack_from("<I", data, offset + size - 4)[0] == size
        block = data[offset:offset+size]
        blocks.append(kind)
        if kind == 0x0A0D0D0A:
            assert struct.unpack_from("<IHHQ", block, 8) == (0x1A2B3C4D, 1, 0, 0xFFFFFFFFFFFFFFFF)
        elif kind == 1:
            assert struct.unpack_from("<HHI", block, 8) == (105, 0, 2304)
            assert b"clock=monotonic_since_boot" in block
        elif kind == 6:
            interface, high, low, captured, original = struct.unpack_from("<IIIII", block, 8)
            index = len(tagged)
            assert interface == 0 and 36 <= captured == original <= 2304
            assert ((high << 32) | low, block[28:28+captured]) == classic_frames[index]
            option_offset = 28 + ((captured + 3) & ~3)
            assert block[28+captured:option_offset] == bytes(option_offset - 28 - captured)
            comments = []
            while option_offset < size - 4:
                code, length = struct.unpack_from("<HH", block, option_offset)
                option_offset += 4
                if code == 0:
                    assert length == 0 and option_offset == size - 4
                    break
                assert code == 1 and option_offset + length <= size - 4
                comments.append(block[option_offset:option_offset+length].decode("ascii"))
                option_offset += (length + 3) & ~3
            assert option_offset == size - 4
            tagged.append(bool(comments))
            if comments:
                fields = dict(item.split("=", 1) for item in comments[0].split())
                assert float(fields["receiver_latitude"]) == position["latitude"]
                assert float(fields["receiver_longitude"]) == position["longitude"]
                assert fields["gps_fix_utc"] == position["fix_utc"]
                assert int(fields["gps_fix_received_us"]) == position["fix_received_us"]
        else:
            raise AssertionError(kind)
        offset += size
    assert offset == len(data) and blocks == [0x0A0D0D0A, 1] + [6] * expected_count
    assert tagged == ([False, True] if expected_count == 2 else [True])
    assert len(classic_frames) == expected_count
print("PASS: GPS receiver JSON/CSV, PCAPNG blocks/options and identical classic PCAP frame bytes")

report = json.loads((root / "test-001.json").read_text())
assert report["mode"] == "experimental-active-wps"
assert report["implementation_candidate"] == "HOSTAPD_LIKE"
assert report["reason"] == "EXPLICIT_RESPONSE_UNCALIBRATED"
assert report["differential_sent"] and report["differential_response"] == "WSC_FRAGMENT_ACK"
assert not report["hardware_calibrated"] and not report["continuation_fragments_sent"]
assert report["tx_accepted_by_driver"] == 6 and report["cleanup_accepted_by_driver"]
assert report["declared_wps_message_length"] == 0 and report["trace_dropped"] == 0
data = (root / "test-001.pcap").read_bytes()
assert struct.unpack_from("<IHHIIII", data) == (0xA1B2C3D4, 2, 4, 0, 0, 2304, 105)
offset = 24
frames = []
for record in report["records"]:
    seconds, micros, captured, original = struct.unpack_from("<IIII", data, offset)
    offset += 16
    assert captured == record["captured"] <= record["original"] == original
    assert captured <= report["captured_bytes_per_frame"]
    packet = data[offset:offset + captured]
    assert len(packet) == captured
    if record["direction"] == "TX_DRIVER_ACCEPTED":
        assert packet[4:10].hex() == report["bssid"].replace(":", "").lower()
        assert packet[10:16].hex() == report["station"].replace(":", "").lower()
    frames.append(packet)
    offset += captured
assert offset == len(data) and len(frames) == report["pcap_frames"] == 12
assert frames[1][0] == 0xB0 and frames[3][0] == 0 and frames[-1][0] == 0xC0
assert frames[3][28:34] == b"\x00\x04Test"
assert frames[5][32:] == b"\x02\x01\x00\x00"  # EAPOL Start.
assert frames[9][36:] == bytes.fromhex("02080010fe00372a0000000104030000")
assert frames[10][36:] == bytes.fromhex("0109000efe00372a000000010600")
print("PASS: experimental WPS report and all 12 protocol records; one zero-length first fragment, no continuation")

report = json.loads((root / "transport-001.json").read_text())
assert report["schema_version"] == 2 and report["mode"] == "experimental-wps-transport"
assert report["driver_transport"] == "scoped-idf447-compatibility" and report["transport_only"]
assert report["reason"] == "TRANSPORT_REACHED_WSC_START" and report["implementation_candidate"] == "UNKNOWN"
assert report["wsc_start_received"] and report["declared_wps_message_length"] is None
assert not report["differential_sent"] and report["differential_response"] == "NOT_OBSERVED"
assert not report["hardware_calibrated"] and not report["continuation_fragments_sent"]
assert report["scan_restored"] and report["scan_was_running"] and report["scan_rx_frames"] == 1
assert report["revalidation"]["advertisements"] == 1 and report["revalidation"]["last_rssi_dbm"] == -55
attempts = report["tx_attempts"]
assert [t["stage"] for t in attempts] == ["AUTHENTICATION", "ASSOCIATION", "EAP_IDENTITY", "WSC_START", "CLEANUP"]
assert [t["compatibility_applied"] for t in attempts] == [True, True, False, False, True]
assert [t["stock_check_error"] for t in attempts] == [0x102, 0x102, 0, 0, 0x102]
assert all(t["driver_error"] == 0 for t in attempts) and report["tx_accepted_by_driver"] == 5
data = (root / "transport-001.pcap").read_bytes()
assert struct.unpack_from("<IHHIIII", data) == (0xA1B2C3D4, 2, 4, 0, 0, 2304, 105)
offset = 24
frames = []
for record in report["records"]:
    _, _, captured, original = struct.unpack_from("<IIII", data, offset)
    offset += 16
    packet = data[offset:offset + captured]
    assert captured == record["captured"] <= original == record["original"] and len(packet) == captured
    if record["direction"] == "TX_DRIVER_ACCEPTED":
        assert packet[4:10].hex() == report["bssid"].replace(":", "").lower()
        assert packet[10:16].hex() == report["station"].replace(":", "").lower()
    frames.append(packet)
    offset += captured
assert offset == len(data) and len(frames) == report["pcap_frames"] == 10
assert frames[-2][36:] == bytes.fromhex("0108000efe00372a000000010100")  # Received WSC Start.
assert frames[-1][0] == 0xC0  # Own-session cleanup is the next and final TX.
assert not any(len(p) >= 50 and p[0] == 8 and p[48:50] == b"\x04\x03" for p in frames)
print("PASS: scoped transport report and 10 PCAP records; WSC Start, own cleanup, observed restored RX, no WPS differential")

report = json.loads((root / "fingerprint-001.json").read_text())
assert report["schema_version"] == 2 and report["mode"] == "experimental-active-wps"
assert report["driver_transport"] == "scoped-idf447-compatibility" and not report["transport_only"]
assert report["wsc_start_received"] and report["differential_sent"]
assert report["differential_response"] == "WSC_FRAGMENT_ACK" and report["implementation_candidate"] == "HOSTAPD_LIKE"
assert report["reason"] == "EXPLICIT_RESPONSE_UNCALIBRATED" and not report["hardware_calibrated"]
assert not report["continuation_fragments_sent"] and report["declared_wps_message_length"] == 0
assert report["scan_restored"] and report["scan_rx_frames"] == 1 and report["cleanup_accepted_by_driver"]
attempts = report["tx_attempts"]
assert [t["stage"] for t in attempts] == ["AUTHENTICATION", "ASSOCIATION", "EAP_IDENTITY", "WSC_START", "WPS_DIFFERENTIAL", "CLEANUP"]
assert [t["compatibility_applied"] for t in attempts] == [True, True, False, False, False, True]
assert all(t["driver_error"] == 0 for t in attempts) and report["tx_accepted_by_driver"] == 6
data = (root / "fingerprint-001.pcap").read_bytes()
assert struct.unpack_from("<IHHIIII", data) == (0xA1B2C3D4, 2, 4, 0, 0, 2304, 105)
offset = 24
frames = []
for record in report["records"]:
    _, _, captured, original = struct.unpack_from("<IIII", data, offset)
    offset += 16
    packet = data[offset:offset + captured]
    assert captured == record["captured"] <= original == record["original"] and len(packet) == captured
    if record["direction"] == "TX_DRIVER_ACCEPTED":
        assert packet[4:10].hex() == report["bssid"].replace(":", "").lower()
        assert packet[10:16].hex() == report["station"].replace(":", "").lower()
    frames.append(packet)
    offset += captured
assert offset == len(data) and len(frames) == report["pcap_frames"] == 12
assert frames[9][36:] == bytes.fromhex("02080010fe00372a0000000104030000")
assert frames[10][36:] == bytes.fromhex("0109000efe00372a000000010600")
assert frames[11][0] == 0xC0
assert len([t for t in attempts if t["stage"] == "WPS_DIFFERENTIAL"]) == 1
print("PASS: compatible WPS fingerprint report and PCAP; one empty first fragment, explicit ACK candidate, no continuation")
