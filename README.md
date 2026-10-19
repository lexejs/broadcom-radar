# Broadcom Radar for M5Stack Cardputer

Portable 2.4 GHz Broadcom Wi-Fi/WPS fingerprint detector for **M5Stack Cardputer ADV** and the **original Cardputer**, installed through M5Launcher. Firmware version: **1.0.10**.

Radar listens to Beacon and already present Probe Response frames, identifies three published Broadcom fingerprints, and shows the evidence on the device. It provides channel hopping or fixed-channel monitoring, a keyboard-driven interface, automatic Broadcom JSON/CSV/PCAP archives and manual scan export to microSD. Passive fingerprints do not establish vulnerability, patch status or safety. Default builds use no active scan, connection or packet-injection APIs. Separate experimental `-T` images add a manual WPS implementation probe using the stock public raw-TX API. The `-C` images test a narrowly scoped driver compatibility path and stop at WSC Start. The new `-F` images use that same path and then submit one empty first fragment to obtain an uncalibrated implementation-family candidate.

## Ready-to-install files

Local builds generate application images and their SHA-256 manifests under `dist/`; generated files are excluded from source history. Version 1.0.10 has not been published to GitHub.

| Hardware | Application image | Size |
| --- | --- | --- |
| Cardputer ADV (Stamp-S3A) | `BRCM-RDR-1.0.10.bin` | 1,006,032 bytes |
| Original Cardputer (Stamp-S3) | `BRCM-RDR-S3-1.0.10.bin` | 1,006,144 bytes |
| ADV, stock WPS probe | `BRCM-RDR-T-1.0.10.bin` | 1,027,728 bytes |
| Original, stock WPS probe | `BRCM-RDR-S3-T-1.0.10.bin` | 1,027,824 bytes |
| ADV, transport-only compatibility | `BRCM-RDR-C-1.0.10.bin` | 1,028,496 bytes |
| Original, transport-only compatibility | `BRCM-RDR-S3-C-1.0.10.bin` | 1,028,592 bytes |
| ADV, compatible WPS fingerprint | `BRCM-RDR-F-1.0.10.bin` | 1,028,496 bytes |
| Original, compatible WPS fingerprint | `BRCM-RDR-S3-F-1.0.10.bin` | 1,028,576 bytes |

Filenames include the firmware version from `include/RadarTypes.h`. The adjacent `.bin.json` files contain exact sizes, SHA-256 hashes and required app partition sizes rounded to 64 KiB. These are **application-only** ESP32-S3 images, starting with `0xE9`. They contain no bootloader, partition table, filesystem image or configuration. Use the binary for your hardware: the ADV build explicitly selects the TCA8418 keyboard reader; the original selects the GPIO matrix reader.

| Validation | Status |
| --- | --- |
| Eight firmware builds, host tests with ASan/UBSan and independent report/PCAP decoding | Passed on the development computer; protocol replies are simulated |
| Cardputer ADV 1.0.7 fingerprint reports | Eleven distinct attempts: four Fragment ACK candidates, one EAP Failure candidate, six timeouts; all restored capture and observed subsequent ads. Implementation-family labels remain uncalibrated |
| Original Cardputer, detailed keyboard/battery checks, independent radio measurement, recovery and long-running stability | Still require hardware acceptance checks |

All eight images require an existing OTA app slot of at least **1,048,576 bytes** after 64 KiB alignment. A read-only Launcher API check on 19 October 2026 found the development ADV Radar slot `brcmrd` at exactly 1,048,576 bytes. Other devices can have different partition layouts; check the actual slot before installation.

## Installation through the existing M5Launcher

1. Keep the existing Launcher installed. Before replacing an app, save its original `.bin`, back up that app and its data using the installed Launcher's backup facilities, and preserve `/config.conf` and `/bkp` on the SD card. Keep an off-card copy of important backups. Check the existing boot-to-Launcher/recovery setting before installation.
2. Open **PMan** or the installed version's partition list. Identify an existing OTA app slot large enough for the `required_aligned_app_partition_bytes` in the selected `.bin.json`. The build enforces a conservative 1.5 MiB maximum, but this is a build guard, not a claim about your device's current free space. The resident Launcher partition must not be selected.
3. Copy the matching `.bin` to the microSD card, for example `/firmware/BRCM-RDR-1.0.10.bin`. FAT32 on an MBR SDHC card is a conservative choice; the installed Launcher may also support other formats. Insert the card.
4. Enter Launcher, open **SD**, select the `.bin`, then the install action. Choose the existing compatible OTA app slot, with the understanding that this replaces its previous app. Menu wording varies by Launcher version. Decline partition resizing, removal, compaction, formatting and filesystem installation if offered. This application needs no data partition. Stop if an existing slot does not fit.
5. Start the installed app. The initial screen should show `BROADCOM RADAR`, `RUNNING`, and a changing channel. Reception is passive; wait through several channel sweeps.

**Do not flash `bootloader.bin`, `partitions.bin`, a merged image or a full dump. Do not run erase-flash.** `partitions-build-only.csv` exists solely for linking and size checking; it is never part of the installation package. Direct `pio run -t upload` is deliberately disabled to protect Launcher.

If you already have a raw partition-table export or a CSV describing the actual installed table, this read-only check verifies that the image fits an existing OTA slot:

```sh
python3 scripts/check_launcher_partition.py dist/BRCM-RDR-1.0.10.bin /path/to/actual-partitions.bin --label app1
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
| F | Cycle display filter: `ALL` -> `WPS` candidates -> `B+W` (Broadcom WPS candidates) |

On the compact keyboard, the arrow positions are **`;` up, `.` down, `,` left, `/` right**. These work directly or through the Fn arrow mapping. **Fn + backtick** is Escape; plain backtick and Backspace also return. Letter commands accept either case. Changes to scan state, filters, results and PCAP buffering are disabled during export; navigation remains available.

The main screen shows running state, channel, hop/fixed mode, SD availability, battery estimate, visible/total AP count and total Broadcom count. The battery value comes from M5Unified and is an estimate. Text is 50% larger (9x12 cells), with five visible APs, a highlighted selection and explicit BRCM+WPS/BRCM/WPS/NONE/WAIT badges. Networks are grouped in that priority order, preserving discovery order within each group and keeping the selected AP when new evidence changes its group. List rows show numeric RSSI in dBm; the unit is written on the details screen so the full combined badge and 11 SSID characters fit on one row. H opens keyboard help and dropped-observation counts. A selected AP has seven pages: overview, reasons, WPS identity, UUIDs, counters and two vendor-IE pages. Printable 32-byte SSIDs span two lines on the overview. Longer escaped values are clipped; exports retain the bounded value.

Since 1.0.10, **F** cycles `ALL` -> `WPS` -> `B+W` -> `ALL`, initially showing all networks. Candidate filters use the same target eligibility check as the manual test: complete data, a known non-hidden SSID, channel 1-13, a valid unicast BSSID and observed WPS. `B+W` additionally requires a Broadcom signature. The footer shows the active filter; `AP:2/7` means two visible out of seven stored APs. Incoming observations update membership automatically. An eligible selection is preserved; when it is excluded, selection moves to the first visible AP. An empty result says `No matching networks`, and Enter/T cannot open a hidden row. Filters affect only the displayed list, preserve all collected records and exports, and do not increase the 128-BSSID capacity. Filter changes are disabled during export and test confirmation/execution. Hidden records are not assessed as safe.

Only changed rows are transferred to the display, at most twice per second for scan updates and immediately for key presses. Each row is composed in a reusable 240x15 RGB565 canvas (7,200 bytes), then sent without clearing the physical display. DMA completes before the buffer is reused. The existing font is scaled, so no additional font assets are linked. Builds use size optimization, LTO and disabled C++ exceptions. The M5GFX build hook keeps its include-dependent base class consistent across translation units for LTO.

## Meaning of results

| Internal status | Display / marker | Meaning |
| --- | --- | --- |
| `BROADCOM_SIGNATURE`, WPS observed | `BRCM DETECTED` / `BRCM+WPS` | Broadcom signature and WPS advertisement observed for the same BSSID; highest display priority |
| `BROADCOM_SIGNATURE`, WPS not observed | `BRCM DETECTED` / `BRCM` | Broadcom signature observed without WPS support being observed |
| `WPS_ONLY` | `WPS / UNKNOWN` / `WPS` | WPS attributes observed without a Broadcom signature |
| `NO_SIGNATURE` | `NO SIGNATURE` / `NONE` | A complete advertisement was parsed without a characteristic signature |
| `INSUFFICIENT_DATA` | `INCONCLUSIVE` / `WAIT` | Only malformed/incomplete attributable advertisements have been observed |

No result establishes vulnerability, patch status or safety. A proprietary IE may originate in a Broadcom driver while the WPS implementation comes from another source. Default builds do not implement active transactions or packet transmission. BSSID OUI attribution is intentionally omitted.

## Experimental on-device WPS tests

All experimental modes require selecting your own named WPS AP, pressing **T**, reviewing the pinned BSSID/channel and pressing **Enter**. **Esc** cancels. Other scan-changing keys are disabled during a test. Automatic BRCM detection never starts an exchange. Hidden SSIDs and unsupported channels cannot start a test. Since 1.0.8, unavailable targets stay on the confirmation screen with their actual blocking reason, such as `Hidden SSID` or `WPS not observed`, instead of returning to the list. The pinned BSSID is refreshed from incoming observations while confirmation is open; later complete name/WPS data can make it eligible. A plus sign is valid SSID data and does not block testing. Since 1.0.9, the list distinguishes `BRCM+WPS` from `BRCM` without observed WPS support. The combined badge is a passive triage cue, not a guarantee that a test can start or that a vulnerable WPS implementation is present. Hidden SSIDs and the other start requirements still apply.

The transport-only baseline uses `cardputer_adv_transport` or `cardputer_transport`, packaged as `-C`. Its confirmation screen says `WPS TRANSPORT TEST`. It waits up to 10 seconds for a fresh matching complete WPS advertisement, then attempts open-system authentication, WPS association, EAP Identity and WSC Start. It stops at a received **WSC Start**, attempts cleanup only for its own station and restores the previous scanner mode. It sends no WPS differential, enrollment payload or continuation. `TRANSPORT_REACHED_WSC_START` still has implementation candidate `UNKNOWN`.

The `-C` and `-F` compatibility builds copy the exact SHA-pinned ESP32-S3 IDF 4.4.7 `libnet80211.a` into its own build directory. Each retains all original instructions, weakens one symbol and gives the original entry a separate alias. A strong wrapper calls the original sanity check first; an `ESP_ERR_INVALID_ARG` result is extended only during the synchronous submission of the current generated AUTH/ASSOC/own-cleanup request. BSSID, own station, stage, body, pending bytes and length are checked. Data frames retain the original checks. The build verifies the actual call target in the linked ELF and the unchanged global SDK hash, and refuses an unreviewed SDK or an image exceeding the current 1 MiB slot. Passive and `-T` builds do not link this compatibility layer. This is an unsupported driver experiment, not evidence of RF transport success.

The new `cardputer_adv_fingerprint` / `cardputer_fingerprint` (`-F`) mode uses the working compatibility transport and continues after WSC Start. Its confirmation screen says `WPS FINGERPRINT TEST` and `One empty WPS fragment`. It submits exactly one first fragment with declared WPS message length zero and no payload or continuation. A valid WSC Fragment ACK maps to `HOSTAPD_LIKE`; a matching EAP Failure or a selected-AP deauthentication with reason 0 after accepted differential TX maps to `BRCM_WPS_LIKE`. The report records `differential_sent` and the exact `differential_response`. A repeated copy of the WSC Start already answered by that fragment is ignored without another TX. Timeouts, other disconnect reasons, unrelated responses and driver rejection yield UNKNOWN. Data frames, including the differential, retain stock driver checks. Cleanup addresses only this generated station.

The older `cardputer_adv_probe` / `cardputer_probe` (`-T`) mode retains the uncalibrated differential: after WSC Start it submits one first fragment with declared WPS message length zero and no payload or continuation. It uses the stock public API. Stock IDF 4.4.7 does not document raw AUTH/ASSOC/cleanup support; real 1.0.5 device reports stopped at authentication TX rejection or advertisement revalidation. `HOSTAPD_LIKE` and `BRCM_WPS_LIKE` remain uncalibrated candidates following the upstream code, whose README describes the opposite response mapping. These candidates do not establish hostapd, a patch, vulnerability or safety.

Each completed attempt writes `/broadcom-radar/test-NNN.json` and `.pcap`, independently of P. JSON is published last. Schema 2 records every bounded TX attempt and its stage, length, API error, actual stock-check result when observable (`null` for stock public API), and whether compatibility was applied. Revalidation counters distinguish missing WPS, malformed ads, SSID/channel mismatch and stale frames; last-target time/RSSI, AP rejection code and capture drops are retained. The 16-record trace captures up to 512 bytes per record, preserves original lengths and includes the first revalidation ad and the accepted one if different. Only driver-accepted TX buffers enter PCAP. The driver may rewrite sequence numbers; acceptance does not prove RF delivery.

Reports are saved after restoring scanner settings and, when previously running, observing advertisements for up to 1.5 seconds. `scan_restored` records API success; `scan_rx_frames=0` explicitly means reception was not observed. A previously paused scanner needs no reception check. Scan errors remain visible on screen. **E** retries saving the retained report after an SD error. Diagnostic EAPOL capture stays restricted to the selected BSSID and this station; restored-reception counts contain no client payloads. Passive scan exports stay advertisement-only.

The 1.0.6 device traces demonstrate successful AUTH/ASSOC/EAP/WSC entry and subsequent scanner RX on three APs, but contain no diagnostic-fragment response. The new `-F` mode reuses this transport without another driver strategy. Compare its responses with a known hostapd control AP and an independent monitor capture before treating a candidate as calibrated. Existing host tests replay the full compatibility workflow with simulated ACK, Failure, reason-0 deauthentication, silence and TX rejection. No patch or vulnerability verdict is inferred.

## Radio and memory decisions

- Default country: **PL**, manual regulatory policy, channels **1-13**, 400 ms dwell. This matches the development location. Set `RADAR_COUNTRY` in `platformio.ini` to the actual operating country before rebuilding elsewhere. `esp_wifi_set_country_code(..., false)` applies the SDK country rules; the returned manual policy/range is verified. Hopping follows that range and never includes channel 14. An 11-channel country restricts the menu and hopping to 1-11.
- Idle STA mode is initialized directly through ESP-IDF. Wi-Fi storage is RAM, NVS credential loading is disabled, and station configuration is empty. No default station network interface or reconnect event handler is created. `esp_wifi_start()` initializes the idle station control block; only `esp_wifi_connect()` would initiate connection/scanning, and that API is not called. `esp_wifi_scan_start()` is also absent.
- The default receive callback accepts only management Beacon/Probe Response frames, checks driver error state and lengths, copies into a **12-frame static FreeRTOS queue** with zero wait, and returns. During a manually started experimental test it also admits selected-AP session replies and EAPOL addressed to this device. Processing, drawing and SD writes happen in the Arduino loop. A driver-owned buffer pointer is never retained.
- Raw frame capacity: **2304 bytes**, excluding FCS. Oversized advertisements are dropped and counted. IDF 4.4.7 `sig_len` includes FCS, so the callback strips its final four bytes before parsing/PCAP.
- AP capacity: **128 BSSIDs**, retained until R/restart. At capacity, existing BSSIDs continue to update; observations of new BSSIDs are dropped and counted. Identical SSIDs do not merge different BSSIDs. Evidence is cumulative; later missing or malformed fields never erase confirmed evidence. RSSI uses the latest observation; maximum RSSI is also retained.
- WPS reassembly: **1024 bytes per advertisement**; text fields: **64 bytes each**; SSID: **32 raw bytes**; vendor IE summaries: **8 per AP**. Oversized text is marked truncated and cannot match a default identity by prefix. Complete nonempty identity fields are retained by completeness/length, not replaced by missing fields. Different matching identity fields across complete advertisements can combine into the default-identity signature; the field mask is exported.
- Malformed advertisements contribute only attributable metadata and counters, not WPS identity/evidence. A later complete advertisement resolves an initially inconclusive entry. Invalid headers, unsupported frame types, invalid BSSIDs and fragmented/protected management frames are discarded. Empty WPS attribute payloads are inconclusive.
- All parser, AP, queue and PCAP storage is bounded. The parsers and aggregation allocate no heap memory. Library initialization and bounded keyboard/SD internals use heap memory. Wi-Fi receive buffers are reduced to four static/eight dynamic buffers and AMPDU reception is disabled. USB serial emits uptime, free/minimum heap and drop counters every five seconds for on-device stability checks.

## Export

Broadcom detections are **saved automatically**, without pressing E or enabling P: `/broadcom-radar/brcm-001.json`, `.csv` and `.pcap` contain one detected BSSID and the raw advertisement that triggered that save. Capture briefly pauses during SD writes and then resumes. A later advertisement creates a new numbered archive only if it adds a Broadcom evidence bit or fills a previously empty WPS identity/UUID field. Repeated advertisements do not write to SD. Deduplication retains the latest 128 distinct saved BSSIDs in RAM, survives R and resets on reboot; older evicted entries can be saved again. An immediately recognizable Broadcom advertisement is archived even when the 128-AP display table is full.

Automatic PCAP contains **one triggering advertisement**, independent of the manual 16-frame ring. The JSON/CSV identity is cumulative for APs in the table, so this one frame need not contain every previously observed field or evidence bit. JSON records `capture_reason: broadcom_detection` and `pcap_scope: triggering_advertisement`. All three files are written as `.part` first; JSON is published last as the completion marker. Errors leave partial files, keep capture usable and permit another attempt on a received Broadcom advertisement after five seconds. There is no pending-frame queue for detections seen while SD is unavailable.

**E** creates `/broadcom-radar/scan-001.json` and `.csv`, then advances to an unused number. Existing final files and interrupted `.part` files are never overwritten. Writes use a 512-byte buffer and one AP or PCAP record per loop iteration. Each completed file is renamed from `.part`; SD errors keep partial files and leave capture usable. A JSON file may finish before a later CSV/PCAP write fails, so a complete set is indicated by all requested final filenames plus the `Saved` message.

JSON includes schema/firmware/hardware, `passive-only`, monotonic timestamps, country, channel mode, channels listened to, receive/drop/malformed counters, bounds, limitations and all AP records. AP records contain BSSID, raw SSID hex, display string, capability flags, WPS fields/UUIDs, individual evidence with source descriptions, status, latest/maximum RSSI, observed channels and advertisement counts.

JSON strings preserve byte values with `\u00XX` escapes; they are not a UTF-8 interpretation of binary SSIDs. `ssid_hex` is authoritative for original bytes. CSV escapes binary bytes as `\xNN`, quotes fields and protects formula-leading values with an apostrophe. SSID hex remains unchanged. Vendor IEs are summarized by prefix/payload length; enable PCAP if the full received IE bytes are needed.

Manual PCAP buffering is **off by default**; automatic BRCM archives always include their triggering frame. Press **P** to retain only the latest **16** advertisements in a fixed ring. E then also writes `scan-001.pcap`. It is a bounded recent snapshot, not a continuous trace. Both passive PCAP types use classic little-endian PCAP with **DLT_IEEE802_11 (105)**, raw 802.11 frames, no RadioTap and no FCS. Timestamps are monotonic uptime in seconds/microseconds, which viewers display near the Unix epoch. There is no wall clock or NTP. RSSI/channel metadata remains in JSON rather than invented RadioTap headers. Data frames, client payloads and EAPOL are never archived by passive scan exports; experimental test reports have their own bounded session trace.

The exported PCAP was independently opened with libpcap/tcpdump and the raw record structure was validated. Wireshark GUI opening has not been performed. This is the standard raw-802.11 PCAP format supported by Wireshark.

An absent SD card does not stop scanning. Pressing E or receiving another eligible Broadcom advertisement after the retry delay retries mounting. SD removal, write failure and rename failure are covered by host fault-injection tests. Physical card compatibility/hot insertion and worst-case card blocking latency are not verified.

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
# Optional experimental on-device WPS probe images:
.venv/bin/pio run -e cardputer_adv_probe -e cardputer_probe
# Optional transport-only compatibility experiment:
.venv/bin/pio run -e cardputer_adv_transport -e cardputer_transport
# Optional compatible WPS implementation fingerprint:
.venv/bin/pio run -e cardputer_adv_fingerprint -e cardputer_fingerprint
bash scripts/test_host.sh
```

The post-build hook produces only application `.bin` files and SHA-256 manifests under `dist/`. Host checks compile production parsers, detector, store, serializers, scanner, UI and exporter with ASan/UBSan. Hardware seams use bounded mock queue, Wi-Fi, display/keyboard and SD backends. Tests cover synthetic signatures, malformed/truncated TLVs/IEs, binary/hidden SSIDs, BSSID separation, aggregation, overflow, callback buffer copying, hopping/hold, country restrictions, controls, no-SD/export faults, file non-overwrite and independent JSON/CSV/PCAP reads. They also exercise 50,000 deterministic damaged inputs. On macOS, LeakSanitizer is unsupported and disabled; address/undefined-behavior sanitizers remain enabled.

[GitHub Actions](.github/workflows/ci.yml) is configured to run host checks and build passive and experimental images for both hardware variants on Ubuntu 24.04. Its firmware artifacts contain application images and SHA-256 manifests. Releases are published separately with the selected binaries; CI does not automatically publish or install firmware. Verify the manifest for the exact image you install: a CI artifact is a separate build from a release image.

`scripts/check_passive.py` checks default Wi-Fi APIs against an explicit allowlist and isolates the experimental public raw-TX transport behind `RADAR_WPS_PROBE`. The separately gated `RADAR_DRIVER_COMPAT` layer is limited to explicit compatibility builds; `RADAR_TRANSPORT_ONLY` keeps `-C` at WSC Start. Default scanner mocks expose no active APIs. Experimental host tests use explicit simulated TX results and protocol replies, including unsupported-driver failure and scan restoration. These checks establish application API behavior, not an over-the-air measurement of the closed-source Wi-Fi driver.

For coverage-guided fuzzing, use a compiler with libFuzzer:

```sh
FUZZ_CXX=/opt/homebrew/opt/llvm/bin/clang++ FUZZ_SECONDS=30 bash scripts/fuzz.sh
```

If that Homebrew path does not exist, use another installed Clang with libFuzzer support. Synthetic seeds are generated from `test/Fixtures.h`; the corpus and sanitizer binaries stay in `.test-build/`. See `RESEARCH.md` for source provenance and precise signature rules.

## Physical acceptance checks still required

Install through the existing Launcher without repartitioning; confirm return to Launcher and restore of the prior app. On both hardware variants check keyboard navigation, SD present/absent, fixed channel and hopping, duplicate SSIDs, report export and several hours of uptime/minimum-heap telemetry. With a separate monitor-mode receiver verify that the Cardputer sends no Probe Request, authentication, association, EAP/WPS, deauthentication or other Wi-Fi traffic while Radar runs. Controlled advertisement fixtures or comparison against an independently captured Beacon trace are needed to validate RSSI/channel/FCS behavior on the actual device. These checks remain pending beyond the user-reported ADV basic operation and display check.
