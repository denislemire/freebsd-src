#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Denis Lemire
# Portable, non-root actual-function tests; never modify the source checkout.
set -eu
[ "$#" = 2 ] || { echo 'usage: run-review-tests.sh SOURCE_CHECKOUT NEW_OUTPUT_DIR' >&2; exit 64; }
src=$(cd "$1" && pwd)
case "$2" in /*) out=$2 ;; *) out=$(pwd)/$2 ;; esac
[ ! -e "$out" ]
tests=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
mkdir -p "$out/include/net80211" "$out/fixtures"
cc=${CC:-cc}
py=${PYTHON:-python3}
base=${HE_TEST_BASE:-12f90bbd3029fedea93e9bb0b1f02c3afafe237b}
git -C "$src" rev-parse HEAD > "$out/source-head.txt"
git -C "$src" diff --binary HEAD -- sys/net80211 sys/compat/linuxkpi > "$out/source-local.diff"
git -C "$src" show "$base:sys/net80211/ieee80211_node.h" > "$out/baseline-node.h"
git -C "$src" show "$base:sys/net80211/_ieee80211.h" > "$out/baseline-rx.h"
nl=${NL80211_HEADER:-$src/sys/compat/linuxkpi/common/include/linux/nl80211.h}
[ -f "$nl" ]
cp "$src/sys/net80211/ieee80211.h" "$src/sys/net80211/ieee80211_he.h" "$src/sys/net80211/_ieee80211.h" "$out/include/net80211/"
cp "$tests"/test_he_*.c "$tests/test_key_retirement.c" "$out/"
cp "$tests/he_cap_proto.h" "$out/"
cp "$tests/fixtures/"*.hex "$out/fixtures/"
"$py" "$tests/build_ies_harness.py" --source "$src/sys" --baseline-header "$out/baseline-node.h" --output "$out/generated_ies_under_test.h" --peer-output "$out/generated_he_peer_under_test.h"
lkpi="$src/sys/compat/linuxkpi/common/include"
"$py" "$tests/build_bitrate_harness.py" "$lkpi/../src/linux_80211.c" "$lkpi/net/cfg80211.h" "$nl" "$out/generated_bitrate_under_test.h"
"$py" "$tests/build_rx_metadata_harness.py" "$lkpi/../src/linux_80211.c" "$lkpi/net/cfg80211.h" "$lkpi/net/mac80211.h" "$src/sys/net80211/_ieee80211.h" "$nl" "$out/baseline-rx.h" "$out/generated_rx_metadata_under_test.h"
"$py" "$tests/build_key_retirement_harness.py" "$lkpi/../src/linux_80211.c" "$out/generated_key_retirement_under_test.h"
cd "$out"
"$cc" --version > compiler.txt
for kind in normal sanitize; do
 if [ "$kind" = sanitize ]; then set -- -g -fsanitize=address,undefined -fno-omit-frame-pointer; else set --; fi
 if [ "$(uname -s)" = Darwin ]; then set -- "$@" '-D__packed=__attribute__((__packed__))'; fi
 for name in cap ies mcs oper peer encode; do
  "$cc" -std=c17 -Wall -Wextra -Werror -DWANT_NET80211 -Iinclude "$@" \
   -Dhe_cap_proto_parse=ieee80211_parse_hecap "$src/sys/net80211/ieee80211_he.c" "test_he_$name.c" -o "test-$name-$kind"
  case "$name" in
   cap|encode) "./test-$name-$kind" fixtures/u6-he-cap.hex ;;
   ies|peer) "./test-$name-$kind" fixtures/u6-he-cap.hex fixtures/u6-he-oper.hex ;;
   oper) "./test-$name-$kind" fixtures/u6-he-oper.hex ;;
   mcs) "./test-$name-$kind" ;;
  esac
 done
 for name in he_bitrate he_rx_metadata key_retirement; do
  "$cc" -std=c17 -Wall -Wextra -Werror "$@" "test_$name.c" -o "test-$name-$kind"
  "./test-$name-$kind"
 done
done
printf '%s\n' 'All normal and ASan/UBSan helper suites passed. Kernel concurrency, live queue-removal coverage and hardware interoperability are not established by this runner.'
