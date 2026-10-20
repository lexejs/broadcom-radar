#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .test-build
compiler="${CXX:-clang++}"
"$compiler" -std=c++17 -g -O1 -Wall -Wextra -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  '-DRADAR_COUNTRY="PL"' -DRADAR_ADV=1 -Iinclude -Itest/stubs \
  test/test_main.cpp src/IeParser.cpp src/WpsParser.cpp src/BroadcomDetector.cpp \
  src/AccessPointStore.cpp src/Serialization.cpp src/GpsTracker.cpp src/WifiScanner.cpp src/Export.cpp src/DisplayUi.cpp src/FieldIndicators.cpp src/WpsProbe.cpp \
  -o .test-build/test-radar
if [[ "$(uname -s)" == Darwin ]]; then
  ASAN_OPTIONS=detect_leaks=0 .test-build/test-radar .test-build
else
  ASAN_OPTIONS=detect_leaks=1 .test-build/test-radar .test-build
fi
"$compiler" -std=c++17 -g -O1 -Wall -Wextra -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  '-DRADAR_COUNTRY="PL"' -DRADAR_ADV=1 -DRADAR_WPS_PROBE=1 -Iinclude -Itest/stubs \
  test/test_probe.cpp src/IeParser.cpp src/WpsParser.cpp src/BroadcomDetector.cpp \
  src/AccessPointStore.cpp src/Serialization.cpp src/GpsTracker.cpp src/WifiScanner.cpp src/Export.cpp src/DisplayUi.cpp src/FieldIndicators.cpp \
  src/WpsProbe.cpp src/WpsProbeRadio.cpp -o .test-build/test-probe
if [[ "$(uname -s)" == Darwin ]]; then
  ASAN_OPTIONS=detect_leaks=0 .test-build/test-probe .test-build
else
  ASAN_OPTIONS=detect_leaks=1 .test-build/test-probe .test-build
fi
"$compiler" -std=c++17 -g -O1 -Wall -Wextra -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  '-DRADAR_COUNTRY="PL"' -DRADAR_ADV=1 -Iinclude -Itest/stubs -Itest \
  test/test_gps.cpp src/IeParser.cpp src/WpsParser.cpp src/BroadcomDetector.cpp \
  src/AccessPointStore.cpp src/Serialization.cpp src/GpsTracker.cpp src/WifiScanner.cpp src/Export.cpp \
  src/DisplayUi.cpp src/FieldIndicators.cpp src/WpsProbe.cpp -o .test-build/test-gps
ASAN_OPTIONS=detect_leaks=0 .test-build/test-gps .test-build
for audio_board in 0 1; do
  "$compiler" -std=c++17 -g -O1 -Wall -Wextra -Werror \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    -DRADAR_ADV="$audio_board" -Iinclude -Itest/stubs \
    test/test_audio.cpp src/CardputerIndicators.cpp src/FieldIndicators.cpp -o .test-build/test-audio
  ASAN_OPTIONS=detect_leaks=0 .test-build/test-audio
done
python3 scripts/check_passive.py
"$compiler" -std=c++17 -g -O1 -Wall -Wextra -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  '-DRADAR_COUNTRY="PL"' -DRADAR_ADV=1 -DRADAR_WPS_PROBE=1 -DRADAR_DRIVER_COMPAT=1 -Iinclude -Itest/stubs \
  test/test_compat.cpp src/IeParser.cpp src/WpsParser.cpp src/BroadcomDetector.cpp \
  src/AccessPointStore.cpp src/Serialization.cpp src/GpsTracker.cpp src/WifiScanner.cpp src/Export.cpp \
  src/WpsProbe.cpp src/WpsProbeRadio.cpp src/DriverCompat.cpp -o .test-build/test-compat
ASAN_OPTIONS=detect_leaks=0 .test-build/test-compat .test-build
"$compiler" -std=c++17 -g -O1 -Wall -Wextra -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  '-DRADAR_COUNTRY="PL"' -DRADAR_ADV=1 -DRADAR_WPS_PROBE=1 -DRADAR_DRIVER_COMPAT=1 -DRADAR_TRANSPORT_ONLY=0 -Iinclude -Itest/stubs \
  test/test_compat.cpp src/IeParser.cpp src/WpsParser.cpp src/BroadcomDetector.cpp \
  src/AccessPointStore.cpp src/Serialization.cpp src/GpsTracker.cpp src/WifiScanner.cpp src/Export.cpp \
  src/WpsProbe.cpp src/WpsProbeRadio.cpp src/DriverCompat.cpp -o .test-build/test-fingerprint
ASAN_OPTIONS=detect_leaks=0 .test-build/test-fingerprint .test-build
python3 scripts/validate_exports.py .test-build
python3 test/test_partition_check.py
if command -v tcpdump >/dev/null 2>&1; then
  tcpdump -n -r .test-build/scan-001.pcap > .test-build/tcpdump.txt 2>&1
  tcpdump -n -r .test-build/brcm-001.pcap > .test-build/tcpdump-brcm.txt 2>&1
  tcpdump -n -r .test-build/test-001.pcap > .test-build/tcpdump-test.txt 2>&1
  tcpdump -n -r .test-build/transport-001.pcap > .test-build/tcpdump-transport.txt 2>&1
  tcpdump -n -r .test-build/fingerprint-001.pcap > .test-build/tcpdump-fingerprint.txt 2>&1
  tcpdump -n -r .test-build/gps-scan-001.pcapng > .test-build/tcpdump-gps.txt 2>&1
  echo 'PASS: libpcap/tcpdump opened exported PCAP and GPS PCAPNG'
fi
