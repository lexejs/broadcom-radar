# Broadcom Radar for M5Stack Cardputer

Portable 2.4 GHz Broadcom Wi-Fi/WPS fingerprint detector for **M5Stack Cardputer ADV** and the **original Cardputer**, installed through M5Launcher. Firmware version: **1.0.1**.

Radar listens to Beacon and already present Probe Response frames, identifies three published Broadcom fingerprints, and shows the evidence on the device. It provides channel hopping or fixed-channel monitoring, a keyboard-driven interface and optional JSON/CSV/PCAP export to microSD. Passive fingerprints do not establish vulnerability, patch status or safety. The application uses no active scan, connection or packet-injection APIs.

## Ready-to-install files

Download application images and their SHA-256 manifests from the [v1.0.1 release](https://github.com/lexejs/broadcom-radar/releases/tag/v1.0.1). Local builds generate the same filenames under `dist/`; generated files are excluded from source history.

| Hardware | Application image | Size |
| --- | --- | --- |
| Cardputer ADV (Stamp-S3A) | [BroadcomRadar-CardputerADV.bin](https://github.com/lexejs/broadcom-radar/releases/download/v1.0.1/BroadcomRadar-CardputerADV.bin) | 1,004,032 bytes |
| Original Cardputer (Stamp-S3) | [BroadcomRadar-Cardputer.bin](https://github.com/lexejs/broadcom-radar/releases/download/v1.0.1/BroadcomRadar-Cardputer.bin) | 1,004,112 bytes |

The adjacent `.bin.json` files contain exact sizes, SHA-256 hashes and required app partition sizes rounded to 64 KiB. These are **application-only** ESP32-S3 images, starting with `0xE9`. They contain no bootloader, partition table, filesystem image or configuration. Use the binary for your hardware: the ADV build explicitly selects the TCA8418 keyboard reader; the original selects the GPIO matrix reader.

| Validation | Status |
| --- | --- |
| Both firmware builds, 95,157 host checks with ASan/UBSan, JSON/CSV and libpcap decoding | Passed on the development computer |
| Cardputer ADV basic operation and updated display | Reported working by the device owner on 18 October 2026 |
| Original Cardputer, physical SD exports, detailed keyboard/battery checks, radio silence, recovery and long-running stability | Still require hardware acceptance checks |

Both images require an existing OTA app slot of at least **1,048,576 bytes** after 64 KiB alignment. A read-only Launcher API check on the development ADV found a 1,114,112-byte slot on 18 October 2026. Other devices can have different partition layouts; check the actual slot before installation.

## Installation through the existing M5Launcher

1. Keep the existing Launcher installed. Before replacing an app, save its original `.bin`, back up that app and its data using the installed Launcher's backup facilities, and preserve `/config.conf` and `/bkp` on the SD card. Keep an off-card copy of important backups. Check the existing boot-to-Launcher/recovery setting before installation.
2. Open **PMan** or the installed version's partition list. Identify an existing OTA app slot large enough for the `required_aligned_app_partition_bytes` in the selected `.bin.json`. The build enforces a conservative 1.5 MiB maximum, but this is a build guard, not a claim about your device's current free space. The resident Launcher partition must not be selected.
3. Copy the matching downloaded `.bin` to the microSD card, for example `/firmware/BroadcomRadar-CardputerADV.bin`. FAT32 on an MBR SDHC card is a conservative choice; the installed Launcher may also support other formats. Insert the card.
4. Enter Launcher, open **SD**, select the `.bin`, then the install action. Choose the existing compatible OTA app slot, with the understanding that this replaces its previous app. Menu wording varies by Launcher version. Decline partition resizing, removal, compaction, formatting and filesystem installation if offered. This application needs no data partition. Stop if an existing slot does not fit.
5. Start the installed app. The initial screen should show `BROADCOM RADAR`, `RUNNING`, and a changing channel. Reception is passive; wait through several channel sweeps.

**Do not flash `bootloader.bin`, `partitions.bin`, a merged image or a full dump. Do not run erase-flash.** `partitions-build-only.csv` exists solely for linking and size checking; it is never part of the installation package. Direct `pio run -t upload` is deliberately disabled to protect Launcher.

If you already have a raw partition-table export or a CSV describing the actual installed table, this read-only check verifies that the image fits an existing OTA slot:

```sh
python3 scripts/check_launcher_partition.py dist/BroadcomRadar-CardputerADV.bin /path/to/actual-partitions.bin --label app1
```

Use the real OTA partition label. This script does not read or write flash, resize partitions or install anything. Without a real table, only image-format and build-limit checks are possible. Current upstream Launcher uses dynamic partitions; an 8 MB flash chip alone does not establish the available app slot size.

## Return to Launcher, rollback and updates

- Pause with **S** and export with **E** if needed. Power-cycle or reset normally, then press **Enter** at the Launcher start screen to enter its menu. This is the documented upstream boot flow. Boot settings and custom bootloaders can change it; use the recovery method already configured in the installed Launcher. Holding **G0** during power-on enters the ESP download mode and is not the normal Launcher return procedure.
- To roll back, enter Launcher and install the saved previous application binary into the same existing OTA slot. Restore its associated data backup if the app requires it. Restoring an application binary alone does not restore that app's data.
- To update Radar, copy the newer matching application `.bin` to SD and repeat installation into the same sufficiently large slot. Radar has no persistent settings or filesystem partition; channel mode, results and PCAP selection reset on restart. Exports on SD remain available.
- Radar disables Wi-Fi NVS credential loading and uses RAM Wi-Fi configuration. It never erases NVS or writes the partition table. Launcher itself controls installation metadata and backup behavior. Current Launcher source can reset the Wi-Fi driver's `net80211` namespace during installation, so preservation of every other application's configuration cannot be guaranteed by Radar. Preserve backups before installation; do not accept installer repartitioning or data-format changes.

These procedures have been checked against upstream Launcher documentation and source, not exercised on physical hardware.

## Controls

| Key | Action |
| --- | --- |
| Up / Down | Select AP; choose channel in the channel menu |
| Left / Right | Select AP; switch detail pages; choose channel |
| Enter | Open details; next detail page; apply selected channel |
| Esc / Backspace | Return to the list |
| S | Pause or resume capture |
| R | Clear APs, counters and buffered PCAP frames; preserve running/paused state |
| E | Export JSON/CSV and optional PCAP; automatically pause capture and restore its prior state |
| M | Choose `HOP` or hold one channel |
| P | Toggle bounded PCAP capture, clearing the previous PCAP buffer |
| H | Open or close keyboard help; view dropped observations |

On the compact keyboard, the arrow positions are **`;` up, `.` down, `,` left, `/` right**. These work directly or through the Fn arrow mapping. **Fn + backtick** is Escape; plain backtick and Backspace also return. Letter commands accept either case. Changes to scan state, results and PCAP buffering are disabled during export; navigation remains available.

The main screen shows running state, channel, hop/fixed mode, SD availability, battery estimate, AP count/capacity and Broadcom count. The battery value comes from M5Unified and is an estimate. Text is 50% larger (9x12 cells), with four visible APs, a highlighted selection and explicit BRCM/WPS/NONE/WAIT badges. H opens keyboard help and dropped-observation counts. A selected AP has seven pages: overview, reasons, WPS identity, UUIDs, counters and two vendor-IE pages. Printable 32-byte SSIDs span two lines on the overview. Longer escaped values are clipped; exports retain the bounded value.

Only changed rows are transferred to the display, at most twice per second for scan updates and immediately for key presses. Each row is composed in a reusable 240x15 RGB565 canvas (7,200 bytes), then sent without clearing the physical display. DMA completes before the buffer is reused. The existing font is scaled, so no additional font assets are linked. Builds use size optimization, LTO and disabled C++ exceptions. The M5GFX build hook keeps its include-dependent base class consistent across translation units for LTO.

## Meaning of results

| Internal status | Display / marker | Meaning |
| --- | --- | --- |
| `BROADCOM_SIGNATURE` | `BRCM DETECTED` / `BRCM` | At least one of the three passive Broadcom signatures was observed in complete advertisements |
| `WPS_ONLY` | `WPS / UNKNOWN` / `WPS` | WPS attributes observed without a Broadcom signature |
| `NO_SIGNATURE` | `NO SIGNATURE` / `NONE` | A complete advertisement was parsed without a characteristic signature |
| `INSUFFICIENT_DATA` | `INCONCLUSIVE` / `WAIT` | Only malformed/incomplete attributable advertisements have been observed |

No result establishes vulnerability, patch status or safety. A proprietary IE may originate in a Broadcom driver while the WPS implementation comes from another source. Firmware does not implement active differential testing, authentication, association, EAP/WPS transactions, deauthentication, packet injection, active scans or probe transmission. BSSID OUI attribution is intentionally omitted.

## Radio and memory decisions

- Default country: **PL**, manual regulatory policy, channels **1-13**, 400 ms dwell. This matches the development location. Set `RADAR_COUNTRY` in `platformio.ini` to the actual operating country before rebuilding elsewhere. `esp_wifi_set_country_code(..., false)` applies the SDK country rules; the returned manual policy/range is verified. Hopping follows that range and never includes channel 14. An 11-channel country restricts the menu and hopping to 1-11.
- Idle STA mode is initialized directly through ESP-IDF. Wi-Fi storage is RAM, NVS credential loading is disabled, and station configuration is empty. No default station network interface or reconnect event handler is created. `esp_wifi_start()` initializes the idle station control block; only `esp_wifi_connect()` would initiate connection/scanning, and that API is not called. `esp_wifi_scan_start()` is also absent.
- The receive callback accepts only management Beacon/Probe Response frames, checks driver error state and lengths, copies into a **12-frame static FreeRTOS queue** with zero wait, and returns. Processing, drawing and SD writes happen in the Arduino loop. A driver-owned buffer pointer is never retained.
- Raw frame capacity: **2304 bytes**, excluding FCS. Oversized advertisements are dropped and counted. IDF 4.4.7 `sig_len` includes FCS, so the callback strips its final four bytes before parsing/PCAP.
- AP capacity: **128 BSSIDs**, retained until R/restart. At capacity, existing BSSIDs continue to update; observations of new BSSIDs are dropped and counted. Identical SSIDs do not merge different BSSIDs. Evidence is cumulative; later missing or malformed fields never erase confirmed evidence. RSSI uses the latest observation; maximum RSSI is also retained.
- WPS reassembly: **1024 bytes per advertisement**; text fields: **64 bytes each**; SSID: **32 raw bytes**; vendor IE summaries: **8 per AP**. Oversized text is marked truncated and cannot match a default identity by prefix. Complete nonempty identity fields are retained by completeness/length, not replaced by missing fields. Different matching identity fields across complete advertisements can combine into the default-identity signature; the field mask is exported.
- Malformed advertisements contribute only attributable metadata and counters, not WPS identity/evidence. A later complete advertisement resolves an initially inconclusive entry. Invalid headers, unsupported frame types, invalid BSSIDs and fragmented/protected management frames are discarded. Empty WPS attribute payloads are inconclusive.
- All parser, AP, queue and PCAP storage is bounded. The parsers and aggregation allocate no heap memory. Library initialization and bounded keyboard/SD internals use heap memory. Wi-Fi receive buffers are reduced to four static/eight dynamic buffers and AMPDU reception is disabled. USB serial emits uptime, free/minimum heap and drop counters every five seconds for on-device stability checks.

## Export

**E** creates `/broadcom-radar/scan-001.json` and `.csv`, then advances to an unused number. Existing final files and interrupted `.part` files are never overwritten. Writes use a 512-byte buffer and one AP or PCAP record per loop iteration. Each completed file is renamed from `.part`; SD errors keep partial files and leave capture usable. A JSON file may finish before a later CSV/PCAP write fails, so a complete set is indicated by all requested final filenames plus the `Saved` message.

JSON includes schema/firmware/hardware, `passive-only`, monotonic timestamps, country, channel mode, channels listened to, receive/drop/malformed counters, bounds, limitations and all AP records. AP records contain BSSID, raw SSID hex, display string, capability flags, WPS fields/UUIDs, individual evidence with source descriptions, status, latest/maximum RSSI, observed channels and advertisement counts.

JSON strings preserve byte values with `\u00XX` escapes; they are not a UTF-8 interpretation of binary SSIDs. `ssid_hex` is authoritative for original bytes. CSV escapes binary bytes as `\xNN`, quotes fields and protects formula-leading values with an apostrophe. SSID hex remains unchanged. Vendor IEs are summarized by prefix/payload length; enable PCAP if the full received IE bytes are needed.

PCAP is **off by default**. Press **P** to retain only the latest **16** advertisements in a fixed ring. E then also writes `scan-001.pcap`. It is a bounded recent snapshot, not a continuous trace. The file uses classic little-endian PCAP with **DLT_IEEE802_11 (105)**, raw 802.11 frames, no RadioTap and no FCS. Timestamps are monotonic uptime in seconds/microseconds, which viewers display near the Unix epoch. There is no wall clock or NTP. RSSI/channel metadata remains in JSON rather than invented RadioTap headers. Data frames, client payloads and EAPOL are never admitted to the ring.

The exported PCAP was independently opened with libpcap/tcpdump and the raw record structure was validated. Wireshark GUI opening has not been performed. This is the standard raw-802.11 PCAP format supported by Wireshark.

An absent SD card does not stop scanning. Pressing E retries mounting. SD removal, write failure and rename failure are covered by host fault-injection tests. Physical card compatibility/hot insertion and worst-case card blocking latency are not verified.

## Build and automated checks

Pinned dependencies:

| Component | Version |
| --- | --- |
| PlatformIO Core used for validation | 6.1.19 |
| `espressif32` platform | 6.13.0 |
| Arduino-ESP32 framework package | 3.20017.241212 (Arduino 2.0.17, ESP-IDF 4.4.7) |
| M5Cardputer | tag 1.2.0, commit `2d4fa6646e4e5b47e0af96214b003aa7b15b8d81` |
| M5Unified | 0.2.26 |
| M5GFX | 0.2.33 |
| IRremote, transitive M5Cardputer dependency, unused by Radar | z3t0 4.7.1 |

Third-party source and license notices are available upstream: [Arduino-ESP32](https://github.com/espressif/arduino-esp32/blob/2.0.17/LICENSE.md), [ESP-IDF](https://github.com/espressif/esp-idf/blob/v4.4.7/LICENSE), [M5Cardputer source headers](https://github.com/m5stack/M5Cardputer/blob/2d4fa6646e4e5b47e0af96214b003aa7b15b8d81/src/M5Cardputer.cpp), [M5Unified](https://github.com/m5stack/M5Unified/blob/0.2.26/LICENSE), [M5GFX](https://github.com/m5stack/M5GFX/blob/0.2.33/LICENSE) and [IRremote](https://github.com/Arduino-IRremote/Arduino-IRremote/blob/v4.7.1/LICENSE).

M5Cardputer's 1.2.0 tag still declares 1.1.1 in `library.json`; the immutable archive commit, rather than that metadata string, identifies the code. Both boards have 8 MB flash and do not require PSRAM. Display is ST7789, 240x135; SD uses CS12/MOSI14/SCK40/MISO39. ADV keyboard is TCA8418 on internal I2C GPIO8/9, interrupt GPIO11. Original keyboard uses the GPIO matrix. ADV expansion-CS GPIO5 is held inactive for SD; this is deliberately not done on the original keyboard's GPIO5.

```sh
python3 -m venv .venv
.venv/bin/pip install platformio==6.1.19
.venv/bin/pio run -e cardputer_adv -e cardputer
bash scripts/test_host.sh
```

The post-build hook produces only application `.bin` files and SHA-256 manifests under `dist/`. Host checks compile production parsers, detector, store, serializers, scanner, UI and exporter with ASan/UBSan. Hardware seams use bounded mock queue, Wi-Fi, display/keyboard and SD backends. Tests cover synthetic signatures, malformed/truncated TLVs/IEs, binary/hidden SSIDs, BSSID separation, aggregation, overflow, callback buffer copying, hopping/hold, country restrictions, controls, no-SD/export faults, file non-overwrite and independent JSON/CSV/PCAP reads. They also exercise 50,000 deterministic damaged inputs. On macOS, LeakSanitizer is unsupported and disabled; address/undefined-behavior sanitizers remain enabled.

[GitHub Actions](.github/workflows/ci.yml) is configured to run host checks and build both firmware variants on Ubuntu 24.04. Its firmware artifacts contain application images and SHA-256 manifests. Releases are published separately with the selected binaries; CI does not automatically publish or install firmware. Verify the manifest for the exact image you install: a CI artifact is a separate build from a release image.

`scripts/check_passive.py` checks production Wi-Fi APIs against an explicit allowlist and rejects active networking layers. The scanner mock exposes no active APIs, so adding one also fails the host compilation. These checks establish application API behavior, not an over-the-air measurement of the closed-source Wi-Fi driver.

For coverage-guided fuzzing, use a compiler with libFuzzer:

```sh
FUZZ_CXX=/opt/homebrew/opt/llvm/bin/clang++ FUZZ_SECONDS=30 bash scripts/fuzz.sh
```

If that Homebrew path does not exist, use another installed Clang with libFuzzer support. Synthetic seeds are generated from `test/Fixtures.h`; the corpus and sanitizer binaries stay in `.test-build/`. See `RESEARCH.md` for source provenance and precise signature rules.

## Physical acceptance checks still required

Install through the existing Launcher without repartitioning; confirm return to Launcher and restore of the prior app. On both hardware variants check keyboard navigation, SD present/absent, fixed channel and hopping, duplicate SSIDs, report export and several hours of uptime/minimum-heap telemetry. With a separate monitor-mode receiver verify that the Cardputer sends no Probe Request, authentication, association, EAP/WPS, deauthentication or other Wi-Fi traffic while Radar runs. Controlled advertisement fixtures or comparison against an independently captured Beacon trace are needed to validate RSSI/channel/FCS behavior on the actual device. These checks remain pending beyond the user-reported ADV basic operation and display check.
