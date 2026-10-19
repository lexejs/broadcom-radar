# Research and implementation boundary

Sources inspected on 2026-10-18 before implementation. This is an independent C++ implementation of the passive fingerprinting rules, without importing Python networking, active test or exploitation code.

## Primary sources

1. [qkaiser/broadcom-wps](https://github.com/qkaiser/broadcom-wps), inspected at commit [`b5b4fe477afae46a1505994e36621ee46ecbf163`](https://github.com/qkaiser/broadcom-wps/tree/b5b4fe477afae46a1505994e36621ee46ecbf163).
2. [`broadcom_fingerprint.py`](https://raw.githubusercontent.com/qkaiser/broadcom-wps/b5b4fe477afae46a1505994e36621ee46ecbf163/broadcom_fingerprint.py), especially `_information_elements()`, `_parse_wps_attributes()` and `parse_advertisement()`.
3. Quentin Kaiser, [One Parser, Two Bugs, Many Routers](https://quentinkaiser.be/security/2026/10/16/one-parser-two-bugs/), published 2026-10-16. The disclosure motivates triage; passive observation does not reproduce its active findings.
4. Espressif, [ESP32-S3 Wi-Fi API, current stable](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-reference/network/esp_wifi.html). Stable currently resolves to a newer major SDK than this build, so implementation also uses the matching [ESP-IDF 4.4.7 API](https://docs.espressif.com/projects/esp-idf/en/v4.4.7/esp32s3/api-reference/network/esp_wifi.html) and the installed `esp_wifi.h` / `esp_wifi_types.h`.
5. [M5Stack M5Cardputer](https://github.com/m5stack/M5Cardputer), immutable [1.2.0 commit](https://github.com/m5stack/M5Cardputer/tree/2d4fa6646e4e5b47e0af96214b003aa7b15b8d81), M5Unified 0.2.26, M5GFX 0.2.33. Official pinouts: [Cardputer ADV](https://docs.m5stack.com/en/core/Cardputer-Adv), [original Cardputer](https://docs.m5stack.com/en/core/Cardputer).
6. [bmorcelli/Launcher](https://github.com/bmorcelli/Launcher), inspected at [`e8cc4dfb35b63aa3dc56eceef58da19e348dda5c`](https://github.com/bmorcelli/Launcher/tree/e8cc4dfb35b63aa3dc56eceef58da19e348dda5c), notably `boards/m5stack-cardputer`, `support_files/custom_8Mb.csv`, `src/main.cpp`, `partition_table_model.cpp`, `partition_install_layout.cpp`, and [boot/install documentation](https://github.com/bmorcelli/Launcher/wiki/Explaining-the-project).

## Exact passive signatures

| Evidence key | Source and implemented condition | Scope of inference |
| --- | --- | --- |
| `broadcom_proprietary_ie` | Vendor IE ID 221, **payload length exactly 9**, first four payload bytes `00 10 18 02` | Broadcom component evidence; a driver can emit this while userspace WPS is unrelated |
| `broadcom_fixed_wps_uuid` | Vendor IE prefix `00 50 F2 04`; WPS big-endian TLV type `0x1047` (UUID-E) or `0x1048` (UUID-R), length exactly 16 and value `000102030405060708090a0b0c0d0ebb` | Characteristic advertised WPS identity; no proof of a vulnerable code path |
| `broadcom_wps_identity_defaults` | At least two **distinct fields** match: Manufacturer `Broadcom`; Model Name `Broadcom` or `BroadcomAP`; Model Number `1234` or `123456`; Device Name `BroadcomAP` | Default-identity fingerprint; no active implementation test |

Text comparisons ignore ASCII case, remove trailing NUL bytes and trim surrounding ASCII whitespace. Exact matches only; a longer value beginning with a default string is not a match. The manufacturer, model, device, model number and serial fields use WPS types `0x1021`, `0x1023`, `0x1011`, `0x1024`, `0x1042`. Serial is exported, not a signature. Unknown attributes are length-checked and skipped.

The upstream default-identity test counts fields, not attribute repetitions. C++ follows that rule. Different fields can also accumulate across complete advertisements for the same BSSID. `identity_default_field_mask` records manufacturer=1, model=2, model number=4, device=8. Every evidence key retains a distinct source description in JSON. No BSSID OUI matching is used.

## Parsing and intentional differences

- Accept raw 802.11 management subtypes 8 and 5 only. The fixed header/body needs 36 bytes: 24-byte MAC header, timestamp, beacon interval and little-endian capability flags. BSSID comes from address 3. A zero/multicast BSSID is rejected. No client identity fallback is used.
- Frame version/type checks are explicit. DS/protected/ordered/fragmented management frames are not interpreted. Sequence/retry announcements otherwise aggregate by BSSID. Advertisements with no SSID IE are incomplete; an SSID IE with zero payload is valid hidden identity. Binary SSIDs remain raw bytes.
- Every IE and TLV read checks remaining bytes before advancing. Offsets use subtraction-based bounds checks. An attributable malformed advertisement is retained for an inconclusive entry, but contributes no signature or WPS identity. This is deliberately stricter than upstream's partial attribute salvage and prevents a truncated frame from creating positive evidence or an unsupported negative result.
- Multiple WPS vendor IEs in one advertisement are concatenated in order within a 1024-byte cap before TLV parsing. This supports attribute splits across IEs. UUID attributes with a length other than 16, incomplete headers/values, oversized reassembly and empty WPS payloads are incomplete data.
- Complete unknown IEs are represented by an IE-ID bitset. At most eight vendor prefix/length summaries are retained per AP; overflow is explicit. Full raw IEs are available in the optional bounded PCAP snapshot. Raw payloads are never treated as unbounded C strings.
- Nonempty WPS values aggregate by completeness and retained length; evidence and characteristic field masks are unions. A later missing WPS IE cannot negate prior evidence. No negative result is represented as a statement that a network is safe.

## Why active assessments are absent

The original scanner has additional logic to distinguish WPS implementations by generated protocol exchanges. Its active assessments cannot be derived from a Beacon. No part of those transactions, authentication, association, fragment generation, EAP/WPS messaging, retransmission or cleanup is ported.

The resulting classification is a direct function of complete observations and the three evidence bits. `BROADCOM_SIGNATURE` takes precedence; otherwise complete WPS observations give `WPS_ONLY`, a complete ad without evidence gives `NO_SIGNATURE`, and only incomplete observations give `INSUFFICIENT_DATA`. Malformed later observations do not downgrade earlier complete evidence.

## ESP-IDF behavior and capture path

The matching API documents describe `esp_wifi_start()` as creating/starting the STA control block and `esp_wifi_connect()` as initiating connection. The default active scan behavior belongs to `esp_wifi_scan_start()`, which is not used. Radar registers no connect/reconnect handler, creates no default station netif, does not load credential NVS, and uses an empty station configuration in RAM. There is no Arduino WiFi wrapper or active networking layer.

Country is applied with the SDK's validated `esp_wifi_set_country_code(country, false)` and checked through `esp_wifi_get_country()`. Automatic country adoption is disabled. The source uses `esp_wifi_set_promiscuous_rx_cb`, a management-only `esp_wifi_set_promiscuous_filter`, `esp_wifi_set_promiscuous`, and manual `esp_wifi_set_channel`. A 400 ms timer advances only while running in hopping mode.

In the installed SDK, `wifi_pkt_rx_ctrl_t.sig_len` is explicitly documented as including FCS. Four bytes are removed from accepted frames. Only copied bytes and primitive RX metadata cross the callback boundary through a statically allocated FreeRTOS queue. No parser, display, storage call, blocking wait or large allocation occurs in the callback. Parser stack scratch is bounded at 1024 bytes and runs outside the Wi-Fi task.

The source API audit and mock integration tests verify the application's passive call paths. Espressif radio/driver internals are closed binary code in this toolchain; absence of all RF transmission is not established by host tests. The physical acceptance check is an independent monitor-mode capture. No claim of that measurement is made.

## Hardware and Launcher constraints

The explicit ADV reader uses the official TCA8418 implementation; the original uses the official GPIO matrix implementation. M5Cardputer's automatic keyboard initialization is bypassed, avoiding initialization of the wrong matrix on ADV. The display and M5Unified internal I2C pin map still use board detection with the matching fallback. SD and display use separate SPI hosts. No PSRAM is assumed.

The current upstream Launcher board supports both devices. Its base 8 MB CSV reserves a protected `app0` test partition for Launcher and current code dynamically manages installed OTA apps. Radar packages a normal application image and does not ship or install a partition table. A conservative 1.5 MiB build guard and per-image aligned-size manifest provide an upper bound; the actual installed OTA slot must independently fit the image. `check_launcher_partition.py` performs a read-only check against a supplied actual table. A read-only Launcher API check on the development ADV on 2026-10-18 found an existing 1,114,112-byte OTA slot; both 1.0.1 images require 1,048,576 aligned bytes. Uploading the ADV image to SD did not modify that table.

## Validation boundary

Host tests compile the production parsers, detector, AP store, scanner, UI, serializers and exporter under address/undefined-behavior sanitizers. Hardware mocks cover callback ownership, bounded queue overflow, channel timing/policy, pause/resume, navigation/export, absent SD, failed/removed SD, write/rename faults and existing-file preservation. Synthetic fixtures cover the three Broadcom signatures independently, ordinary WPS, no WPS, UUID-E/R, identical SSIDs on different BSSIDs, empty/binary SSIDs, duplicate fields, split WPS IEs, malformed lengths and 50,000 deterministic random inputs. Coverage-guided fuzzing runs separately.

PCAP serialization is verified with an independent binary decoder and libpcap/tcpdump: link type 105, classic PCAP, lengths/timestamps and raw management frames. No RadioTap header is synthesized. On 2026-10-18 the device owner reported that 1.0.1 works on Cardputer ADV after the display update. Wireshark GUI, original Cardputer operation and detailed hardware acceptance tests remain unperformed. Compilation, mocks and the basic ADV report do not establish radio sensitivity, regulatory behavior in hardware, battery accuracy, worst-case SD latency, absence of watchdog resets, long-duration heap stability or recovery on the installed bootloader.
