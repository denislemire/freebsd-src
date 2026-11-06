/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Denis Lemire. */
#ifndef HPBSD_HE_CAP_PROTO_H
#define HPBSD_HE_CAP_PROTO_H

#include <sys/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <net80211/ieee80211.h>

/*
 * Experimental parser, not an installed kernel API.  Input includes Element
 * ID, Length and Element ID Extension.  Output must not overlap input.
 * Unknown trailing bytes within the declared IE are ignored.  Missing MCS
 * bandwidth maps are normalized to "not supported" (all bits set).
 * On error, clear output so an old peer's capabilities cannot survive.
 */
int he_cap_proto_parse(const uint8_t *, size_t, struct net80211_he_cap *);

#endif
