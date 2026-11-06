#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Denis Lemire
"""Extract the real helper for modeled queue tests, not kernel concurrency proof."""
import argparse
import hashlib
import json
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('source', type=Path)
p.add_argument('output', type=Path)
a = p.parse_args()
s = a.source.read_text()
start = s.index('static u_int\nlkpi_discard_key_txq(')
brace = s.index('{', start)
depth = 0
for end in range(brace, len(s)):
    depth += (s[end] == '{') - (s[end] == '}')
    if depth == 0:
        break
else:
    raise SystemExit('Unbalanced helper body')
function = s[start:end + 1] + '\n'
license_text = s[:s.index('\n/*\n * Public functions')]
a.output.write_text(license_text + '\n/* Actual helper, modeled queue API in test file. */\n' + function)
print(json.dumps({'source_sha256': hashlib.sha256(s.encode()).hexdigest(),
                  'function_sha256': hashlib.sha256(function.encode()).hexdigest()}))
