#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
compiler="${FUZZ_CXX:-clang++}"
mkdir -p .test-build/corpus
"$compiler" -std=c++17 -Itest test/generate_corpus.cpp -o .test-build/generate-corpus
.test-build/generate-corpus .test-build/corpus
"$compiler" -std=c++17 -g -O1 -fsanitize=fuzzer,address,undefined \
  -fno-omit-frame-pointer -Iinclude test/fuzz_parser.cpp \
  src/IeParser.cpp src/WpsParser.cpp src/BroadcomDetector.cpp src/AccessPointStore.cpp \
  -o .test-build/fuzz-parser
.test-build/fuzz-parser .test-build/corpus -max_total_time="${FUZZ_SECONDS:-30}" \
  -max_len=2400 -timeout=2 -rss_limit_mb=768 -artifact_prefix=.test-build/
