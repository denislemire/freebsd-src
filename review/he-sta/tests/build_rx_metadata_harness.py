#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Denis Lemire
"""Extract native/Linux RX definitions and the actual HE metadata conversion."""
import argparse
import hashlib
import re
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
for name in ('source', 'cfg', 'mac', 'native', 'nl', 'baseline', 'output'):
    p.add_argument(name, type=Path)
a = p.parse_args()
inputs = [a.source, a.cfg, a.mac, a.native, a.nl, a.baseline]
src, cfg, mac, native, nl, baseline = [v.read_text() for v in inputs]


def block(text, expression):
    match = re.search(expression, text)
    if not match:
        raise SystemExit('missing block: ' + expression)
    start = text.index('{', match.start())
    cursor, depth = start + 1, 1
    while depth:
        depth += (text[cursor] == '{') - (text[cursor] == '}')
        cursor += 1
    if cursor < len(text) and text[cursor] == ';':
        cursor += 1
    return text[match.start():cursor]


licenses = []
for text in (src, cfg, mac, native, nl, baseline):
    license = re.match(r'/\*.*?\*/', text, re.S).group()
    if license not in licenses:
        licenses.append(license)
hashes = '\n'.join('/* SHA256 ' + hashlib.sha256(v.read_bytes()).hexdigest()
                   + ' (' + v.name + ') */' for v in inputs)
defines = '\n'.join(line for line in native.splitlines()
                    if re.match(r'#define\s+IEEE80211_(?:MAX_CHAINS|MAX_EVM_PILOTS|RX_F_\w+|RX_HE_\w+)\s', line))
typedef = re.search(r'typedef\s+int8_t\s+net80211_rssi_t;', native)
if not typedef:
    raise SystemExit('unexpected native RSSI type; review the harness')
parts = licenses + [hashes,
    '#include <stdint.h>\n#include <stdbool.h>\n#define BIT(n) (1U << (n))',
    defines, typedef.group(),
    block(cfg, r'enum rate_info_bw\s*\{'),
    block(nl, r'enum nl80211_he_gi\s*\{'),
    block(nl, r'enum nl80211_he_ru_alloc\s*\{'),
    block(mac, r'enum ieee80211_rx_status_flags\s*\{'),
    block(mac, r'struct ieee80211_rx_status\s*\{'),
    block(native, r'struct ieee80211_rx_stats\s*\{'),
    block(baseline, r'struct ieee80211_rx_stats\s*\{').replace(
        'struct ieee80211_rx_stats', 'struct ieee80211_rx_stats_baseline', 1),
    block(src, r'static void\nlkpi_convert_he_rx_stats\(')]
a.output.write_text('\n\n'.join(parts) + '\n')
