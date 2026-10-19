#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .test-build
compiler="${CXX:-clang++}"
"$compiler" -std=c++17 -g -O1 -Wall -Wextra -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  '-DRADAR_COUNTRY="PL"' -DRADAR_ADV=1 -Iinclude -Itest/stubs \
  test/test_main.cpp src/IeParser.cpp src/WpsParser.cpp src/BroadcomDetector.cpp \
  src/AccessPointStore.cpp src/Serialization.cpp src/WifiScanner.cpp src/Export.cpp src/DisplayUi.cpp src/WpsProbe.cpp \
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
  src/AccessPointStore.cpp src/Serialization.cpp src/WifiScanner.cpp src/Export.cpp src/DisplayUi.cpp \
  src/WpsProbe.cpp src/WpsProbeRadio.cpp -o .test-build/test-probe
if [[ "$(uname -s)" == Darwin ]]; then
  ASAN_OPTIONS=detect_leaks=0 .test-build/test-probe .test-build
else
  ASAN_OPTIONS=detect_leaks=1 .test-build/test-probe .test-build
fi
python3 scripts/check_passive.py
python3 scripts/validate_exports.py .test-build
python3 test/test_partition_check.py
if command -v tcpdump >/dev/null 2>&1; then
  tcpdump -n -r .test-build/scan-001.pcap > .test-build/tcpdump.txt 2>&1
  tcpdump -n -r .test-build/brcm-001.pcap > .test-build/tcpdump-brcm.txt 2>&1
  tcpdump -n -r .test-build/test-001.pcap > .test-build/tcpdump-test.txt 2>&1
  echo 'PASS: libpcap/tcpdump opened exported PCAP'
fi
