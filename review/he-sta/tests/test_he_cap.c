/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Denis Lemire. */
#include <sys/param.h>
#include <sys/endian.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "he_cap_proto.h"

static unsigned int checks;

static void
expect(int condition)
{
	checks++;
	assert(condition);
}

static int
is_clear(const struct net80211_he_cap *cap)
{
	const uint8_t *p = (const uint8_t *)cap;
	size_t i;

	for (i = 0; i < sizeof(*cap); i++)
		if (p[i] != 0)
			return (0);
	return (1);
}

/* Construct distinguishable little-endian maps, including the sparse case. */
static size_t
make_ie(uint8_t *ie, unsigned int widths, int ppe_header)
{
	unsigned int bits, ru, nss;
	size_t n, ppe_len;

	memset(ie, 0, 64);
	ie[0] = IEEE80211_ELEMID_EXTFIELD;
	ie[2] = IEEE80211_ELEMID_EXT_HE_CAPA;
	/* 40/80 MHz support alone must not consume a 160 MHz MCS tuple. */
	ie[3 + 6] = IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G |
	    ((widths & 1) ? IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G : 0) |
	    ((widths & 2) ? IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G : 0);
	n = 3 + sizeof(struct ieee80211_he_cap_elem);
	le16enc(ie + n, 0xfffa);
	le16enc(ie + n + 2, 0xfff9);
	n += 4;
	if (widths & 1) {
		le16enc(ie + n, 0xfffe);
		le16enc(ie + n + 2, 0xfffd);
		n += 4;
	}
	if (widths & 2) {
		le16enc(ie + n, 0xffee);
		le16enc(ie + n + 2, 0xffdd);
		n += 4;
	}
	if (ppe_header >= 0) {
		ie[3 + 6 + 6] |= IEEE80211_HE_PHY_CAP6_PPE_THRESHOLD_PRESENT;
		nss = (ppe_header & 7) + 1;
		ru = ((unsigned int)ppe_header >> 3) & 15;
		bits = 0;
		while (ru != 0) {
			bits += ru & 1;
			ru >>= 1;
		}
		ppe_len = (7 + nss * bits * 6 + 7) / 8;
		memset(ie + n, 0xa5, ppe_len);
		ie[n] = (uint8_t)ppe_header;
		n += ppe_len;
	}
	ie[1] = (uint8_t)(n - 2);
	return (n);
}

static void
test_one(unsigned int widths, int ppe_header)
{
	struct net80211_he_cap cap;
	uint8_t ie[64], *cut;
	size_t n, i;

	n = make_ie(ie, widths, ppe_header);
	expect(he_cap_proto_parse(ie, n, &cap) == 0);
	expect(cap.has_he);
	expect(le16toh(cap.he_mcs_nss_supp.rx_mcs_80) == 0xfffa);
	expect(le16toh(cap.he_mcs_nss_supp.tx_mcs_80) == 0xfff9);
	expect(le16toh(cap.he_mcs_nss_supp.rx_mcs_160) ==
	    ((widths & 1) ? 0xfffe : 0xffff));
	expect(le16toh(cap.he_mcs_nss_supp.tx_mcs_160) ==
	    ((widths & 1) ? 0xfffd : 0xffff));
	expect(le16toh(cap.he_mcs_nss_supp.rx_mcs_80p80) ==
	    ((widths & 2) ? 0xffee : 0xffff));
	expect(le16toh(cap.he_mcs_nss_supp.tx_mcs_80p80) ==
	    ((widths & 2) ? 0xffdd : 0xffff));
	if (ppe_header < 0)
		expect(cap.ppe_thres[0] == 0);
	else
		expect(cap.ppe_thres[0] == (uint8_t)ppe_header);

	/* Exact allocations let ASan detect reads past each truncated element. */
	for (i = 0; i < n; i++) {
		cut = malloc(i == 0 ? 1 : i);
		expect(cut != NULL);
		memcpy(cut, ie, i);
		memset(&cap, 0xa5, sizeof(cap));
		expect(he_cap_proto_parse(cut, i, &cap) != 0);
		expect(is_clear(&cap));
		if (i >= 2) {
			/* Also truncate the declared length, exercising inner checks. */
			cut[1] = (uint8_t)(i - 2);
			memset(&cap, 0xa5, sizeof(cap));
			expect(he_cap_proto_parse(cut, i, &cap) != 0);
			expect(is_clear(&cap));
		}
		free(cut);
	}
}

static void
test_fixture(const char *path)
{
	struct net80211_he_cap cap;
	uint8_t ie[257];
	unsigned int v;
	size_t n;
	FILE *f;

	f = fopen(path, "r");
	expect(f != NULL);
	n = 0;
	while (fscanf(f, "%2x", &v) == 1) {
		expect(n < sizeof(ie));
		ie[n++] = (uint8_t)v;
	}
	expect(fclose(f) == 0);
	expect(he_cap_proto_parse(ie, n, &cap) == 0);
	/* This fixture is the captured U6 element, not an arbitrary input file. */
	expect(n == 37);
	expect(cap.has_he);
	expect(le16toh(cap.he_mcs_nss_supp.rx_mcs_80) == 0xffaa);
	expect(le16toh(cap.he_mcs_nss_supp.tx_mcs_80) == 0xffaa);
	expect(le16toh(cap.he_mcs_nss_supp.rx_mcs_160) == 0xffff);
	expect(le16toh(cap.he_mcs_nss_supp.rx_mcs_80p80) == 0xffff);
	expect(cap.ppe_thres[0] == 0x7b);
	printf("Captured HE IE: %zu bytes, <=80 RX/TX maps %#x/%#x, HE=%d\n",
	    n, le16toh(cap.he_mcs_nss_supp.rx_mcs_80),
	    le16toh(cap.he_mcs_nss_supp.tx_mcs_80), cap.has_he);
}

int
main(int argc, char **argv)
{
	struct net80211_he_cap cap;
	uint8_t ie[64];
	unsigned int widths;
	int ppe;

	for (widths = 0; widths < 4; widths++) {
		test_one(widths, -1);
		for (ppe = 0; ppe < 128; ppe++)
			test_one(widths, ppe);
	}
	make_ie(ie, 0, -1);
	/* Deliberate forward-tolerance policy for extra declared bytes. */
	ie[1] += 2;
	expect(he_cap_proto_parse(ie, 26, &cap) == 0);
	expect(cap.has_he);
	make_ie(ie, 0, -1);
	ie[0] = IEEE80211_ELEMID_SSID;
	expect(he_cap_proto_parse(ie, 24, &cap) == EINVAL);
	expect(is_clear(&cap));
	make_ie(ie, 0, -1);
	ie[2]++;
	memset(&cap, 0xa5, sizeof(cap));
	expect(he_cap_proto_parse(ie, 24, &cap) == EINVAL);
	expect(is_clear(&cap));
	expect(he_cap_proto_parse(NULL, 0, &cap) == EINVAL);
	expect(is_clear(&cap));
	expect(he_cap_proto_parse(ie, 24, NULL) == EINVAL);
	if (argc == 2)
		test_fixture(argv[1]);
	printf("PASS: %u checks across 516 synthetic HE layouts.\n", checks);
	return (0);
}
