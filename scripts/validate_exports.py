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
