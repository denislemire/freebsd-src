#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Denis Lemire
"""Extract the actual HE helper/dispatcher and native rate definitions."""
import argparse
import hashlib
import re
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('source', type=Path)
p.add_argument('cfg80211', type=Path)
p.add_argument('nl80211', type=Path)
p.add_argument('output', type=Path)
a = p.parse_args()
source, cfg, nl = [v.read_text() for v in (a.source, a.cfg80211, a.nl80211)]


def declaration(text, kind, name):
    match = re.search(r'\b' + kind + r'\s+' + name + r'\s*\{[^}]+\};', text)
    if not match:
        raise SystemExit('missing declaration: ' + name)
    return match.group()


def function(name):
    match = re.search(r'(?:static )?uint32_t\n' + name +
                      r'\(struct rate_info \*rate\)\n\{', source)
    if not match:
        raise SystemExit('missing function: ' + name)
    cursor = match.end()
    depth = 1
    while depth:
        if source[cursor] == '{':
            depth += 1
        elif source[cursor] == '}':
            depth -= 1
        cursor += 1
    return source[match.start():cursor]


# Retain the complete licenses from every source represented in the extract.
licenses = []
for text in (source, cfg, nl):
    match = re.match(r'/\*.*?\*/', text, re.S)
    if not match:
        raise SystemExit('missing leading license')
    if match.group() not in licenses:
        licenses.append(match.group())
identities = '\n'.join('/* input SHA256: ' + hashlib.sha256(v.read_bytes()).hexdigest()
                       + ' (' + v.name + ') */'
                       for v in (a.source, a.cfg80211, a.nl80211))
parts = licenses + [identities, '#include <stdint.h>\n#define BIT(n) (1U << (n))',
    declaration(cfg, 'enum', 'cfg80211_rate_info_flags'),
    declaration(cfg, 'enum', 'rate_info_bw'),
    declaration(cfg, 'struct', 'rate_info'),
    declaration(nl, 'enum', 'nl80211_he_gi'),
    declaration(nl, 'enum', 'nl80211_he_ru_alloc'),
    '#define IMPROVE(...) ((void)0)',
    # Sentinels verify dispatch without pretending to retest unchanged HT/VHT.
    'static uint32_t lkpi_cfg80211_calculate_bitrate_ht(struct rate_info *r) '
    '{ (void)r; return 111111; }',
    'static uint32_t lkpi_cfg80211_calculate_bitrate_vht(struct rate_info *r) '
    '{ (void)r; return 222222; }',
    function('lkpi_cfg80211_calculate_bitrate_he'),
    function('linuxkpi_cfg80211_calculate_bitrate')]
a.output.write_text('\n\n'.join(parts) + '\n')
