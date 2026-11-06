/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Denis Lemire. */
#include <sys/types.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_he.h>

static unsigned int checks;
#define CHECK(x) do { checks++; assert(x); } while (0)

int
main(void)
{
	/* Fixed protocol truth table: 0/1/2 are increasing supported ranges;
	 * 3 means unsupported and overrides any supported range. */
	static const uint8_t expected[4][4] = {
		{0, 0, 0, 3}, {0, 1, 1, 3},
		{0, 1, 2, 3}, {3, 3, 3, 3}
	};
	static const bool basic_supported[4][4] = {
		{true, false, false, true}, {true, true, false, true},
		{true, true, true, true}, {false, false, false, true}
	};
	uint16_t a, b, want, mask, peer_rx, peer_tx;
	unsigned int stream, x, y;

	for (stream = 0; stream < 8; stream++) {
		mask = (uint16_t)(3U << (2 * stream));
		for (x = 0; x < 4; x++) {
			for (y = 0; y < 4; y++) {
				a = (uint16_t)((0xffffU & ~mask) |
				    (x << (2 * stream)));
				b = (uint16_t)((0xffffU & ~mask) |
				    (y << (2 * stream)));
				want = (uint16_t)((0xffffU & ~mask) |
				    (expected[x][y] << (2 * stream)));
				CHECK(ieee80211_he_mcs_intersect(a, b) == want);
				CHECK(ieee80211_he_mcs_supports_basic(a, b) ==
				    basic_supported[x][y]);
			}
		}
	}
	CHECK(ieee80211_he_mcs_intersect(0xffff, 0) == 0xffff);
	CHECK(ieee80211_he_mcs_intersect(0, 0xffff) == 0xffff);
	CHECK(ieee80211_he_mcs_intersect(0, 0) == 0);
	CHECK(ieee80211_he_mcs_intersect(0xfffa, 0xffaa) == 0xfffa);

	/* Synthetic asymmetric endpoints, all values in host order:
	 * local RX: 1 stream MCS0-11; local TX: 2 streams MCS0-9;
	 * peer RX: 4 streams MCS0-7; peer TX: 2 streams MCS0-11.
	 * Results retain the PEER's RX/TX perspective, as driver peer state must. */
	peer_rx = ieee80211_he_mcs_intersect(0xfff5, 0xff00);
	peer_tx = ieee80211_he_mcs_intersect(0xfffa, 0xfffe);
	CHECK(peer_rx == 0xfff0);
	CHECK(peer_tx == 0xfffe);
	CHECK(peer_rx != ieee80211_he_mcs_intersect(0xfffe, 0xff00));
	CHECK(peer_tx != ieee80211_he_mcs_intersect(0xfff5, 0xfffa));
	CHECK(ieee80211_he_mcs_supports_basic(0xfffa, 0xfffc));
	CHECK(ieee80211_he_mcs_supports_basic(0xfffa, 0xfff0));
	CHECK(!ieee80211_he_mcs_supports_basic(0xfffa, 0xffc0));
	CHECK(!ieee80211_he_mcs_supports_basic(0xfffe, 0xfff0));
	CHECK(ieee80211_he_mcs_supports_basic(0xffff, 0xffff));
	printf("PASS: %u HE MCS checks, including asymmetric TX/RX fixtures.\n",
	    checks);
	return (0);
}
