#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Denis Lemire
"""Extract actual BSD IE routines for user-space ownership tests, not replicas."""
import argparse
import hashlib
from pathlib import Path
import re

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source", type=Path, required=True, help="FreeBSD sys directory")
parser.add_argument("--baseline-header", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--peer-output", type=Path)
args = parser.parse_args()
header = args.source / "net80211/ieee80211_node.h"
implementation = args.source / "net80211/ieee80211_node.c"


def extract(pattern, text):
    matches = re.findall(pattern, text, re.MULTILINE | re.DOTALL)
    if len(matches) != 1:
        raise SystemExit(f"Expected exactly one source match: {pattern!r}")
    return matches[0]


code = implementation.read_text()
notices = []
for text in (code, header.read_text(), args.baseline_header.read_text()):
    notice = extract(r"\A(/\*-.*?\*/)", text)
    if notice not in notices:
        notices.append(notice)
record = r"^(struct ieee80211_ies \{.*?^\};)"
old = extract(record, args.baseline_header.read_text())
new = extract(record, header.read_text())
parts = notices + ["/* Generated from identified native sources; do not edit. */",
         old.replace("struct ieee80211_ies", "struct baseline_ieee80211_ies", 1), new]
for name in ("init", "cleanup", "expand"):
    parts.append(extract(r"^((?:int|void)\nieee80211_ies_" + name + r"\(.*?^\})", code))
args.output.write_text("\n\n".join(parts) + "\n")
for path in (implementation, header, args.baseline_header, args.output):
    print(f"SHA256 ({path}) = {hashlib.sha256(path.read_bytes()).hexdigest()}")
if args.peer_output:
    source = args.source / "net80211/ieee80211_he.c"
    text = source.read_text()
    parts = [extract(r"\A(/\*-.*?\*/)", text)]
    flags = ("IEEE80211_FEXT_HE", "IEEE80211_FHT_HT", "IEEE80211_FVHT_VHT",
             "IEEE80211_NODE_HE", "IEEE80211_NODE_HT", "IEEE80211_NODE_VHT",
             "IEEE80211_NODE_QOS")
    definitions = (args.source / "net80211/ieee80211_var.h").read_text() + header.read_text()
    for flag in flags:
        parts.append(extract(r"^(#define[ \t]+" + flag + r"[ \t]+[^\n]+)", definitions))
    for name in ("ieee80211_get_hecap", "he_ie_available", "ieee80211_he_prepare_peer",
                 "he_state_reset", "ieee80211_he_node_cleanup", "ieee80211_he_node_free",
                 "ieee80211_he_get_state", "ieee80211_he_was_advertised",
                 "ieee80211_he_request_advertised", "he_sta_policy",
                 "ieee80211_he_prepare_request", "ieee80211_he_accept_response",
                 "ieee80211_he_update_operation"):
        parts.append(extract(r"^((?:static )?(?:int|size_t|void|bool)\n" + name + r"\(.*?^\})", text))
    args.peer_output.write_text("\n\n".join(parts) + "\n")
    for path in (source, args.peer_output):
        print(f"SHA256 ({path}) = {hashlib.sha256(path.read_bytes()).hexdigest()}")
