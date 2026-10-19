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

report = json.loads((root / "test-001.json").read_text())
assert report["mode"] == "experimental-active-wps"
assert report["implementation_candidate"] == "HOSTAPD_LIKE"
assert report["reason"] == "EXPLICIT_RESPONSE_UNCALIBRATED"
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
