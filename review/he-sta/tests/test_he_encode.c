/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Denis Lemire. */
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_he.h>

static unsigned int checks;
#define CHECK(x) do { checks++; assert(x); } while (0)

static void
reject(const struct net80211_he_cap *cap, size_t len, int error)
{
	uint8_t *out;
	size_t n, i;

	out = malloc(len == 0 ? 1 : len);
	CHECK(out != NULL);
	memset(out, 0xa5, len);
	n = 999;
	CHECK(ieee80211_encode_hecap(cap, out, len, &n) == error);
	CHECK(n == 0);
	for (i = 0; i < len; i++)
		CHECK(out[i] == 0xa5);
	free(out);
}

int
main(int argc, char **argv)
{
	/* Independent mandatory <=80 MHz wire image: no MAC features or PPE. */
	static const uint8_t golden[24] = {
		0xff, 22, 35, 0, 0, 0, 0, 0, 0,
		4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0xfa, 0xff, 0xf9, 0xff
	};
	struct net80211_he_cap cap, parsed;
	uint8_t fixture[64], expected[64], encoded[64], *exact, *maps;
	size_t n, i, length, required, ppe_len;
	unsigned int widths, ru, nss, nrus, bit, byte;
	int ppe;
	FILE *file;

	CHECK(argc == 2);
	memset(&cap, 0xa5, sizeof(cap));
	cap.has_he = true;
	memset(&cap.he_cap_elem, 0, sizeof(cap.he_cap_elem));
	cap.he_cap_elem.phy_cap_info[0] = 4;
	maps = (uint8_t *)&cap.he_mcs_nss_supp;
	maps[0] = 0xfa; maps[1] = 0xff;
	maps[2] = 0xf9; maps[3] = 0xff;
	memset(encoded, 0xa5, sizeof(encoded));
	CHECK(ieee80211_encode_hecap(&cap, encoded, sizeof(encoded), &n) == 0);
	CHECK(n == sizeof(golden));
	CHECK(memcmp(encoded, golden, n) == 0);
	for (i = n; i < sizeof(encoded); i++)
		CHECK(encoded[i] == 0xa5);
	for (i = 0; i < sizeof(golden); i++)
		reject(&cap, i, EMSGSIZE);
	CHECK(ieee80211_encode_hecap(&cap, NULL, 0, &required) == 0);
	CHECK(required == sizeof(golden));
	CHECK(ieee80211_encode_hecap(&cap, NULL, 1, &required) == EINVAL);
	CHECK(required == 0);
	CHECK(ieee80211_encode_hecap(&cap, encoded, sizeof(encoded), NULL) == EINVAL);
	reject(NULL, 64, EINVAL);
	cap.has_he = false;
	reject(&cap, 64, ENOTSUP);
	cap.has_he = true;
	maps[0] |= 3;
	reject(&cap, 64, EINVAL);
	maps[0] = 0xfa;
	maps[2] |= 3;
	reject(&cap, 64, EINVAL);
	maps[2] = 0xf9;

	/* Fixed length formula independent of the implementation.  Cover every
	 * PPE NSS/RU mask and all four optional MCS-map combinations. */
	for (widths = 0; widths < 4; widths++) {
		for (ppe = -1; ppe < 128; ppe++) {
			cap.he_cap_elem.phy_cap_info[0] = 4 |
			    ((widths & 1) ? 8 : 0) | ((widths & 2) ? 16 : 0);
			cap.he_cap_elem.phy_cap_info[6] = ppe < 0 ? 0 : 0x80;
			memcpy(expected, golden, sizeof(golden));
			expected[9] = cap.he_cap_elem.phy_cap_info[0];
			expected[15] = cap.he_cap_elem.phy_cap_info[6];
			length = 24;
			for (i = 4; i < 12; i++)
				maps[i] = (uint8_t)(0x80 + i);
			if (widths & 1) {
				memcpy(expected + length, maps + 4, 4);
				length += 4;
			}
			if (widths & 2) {
				memcpy(expected + length, maps + 8, 4);
				length += 4;
			}
			if (ppe >= 0) {
				nss = (ppe & 7) + 1;
				ru = ((unsigned int)ppe >> 3) & 15;
				nrus = 0;
				for (bit = 0; bit < 4; bit++)
					nrus += (ru >> bit) & 1;
				memset(cap.ppe_thres, 0x5a, sizeof(cap.ppe_thres));
				cap.ppe_thres[0] = (uint8_t)ppe;
				if (ru == 0) {
					reject(&cap, 64, EINVAL);
					continue;
				}
				ppe_len = (7 + 6 * nss * nrus + 7) / 8;
				memcpy(expected + length, cap.ppe_thres, ppe_len);
				length += ppe_len;
			}
			expected[1] = (uint8_t)(length - 2);
			CHECK(ieee80211_encode_hecap(&cap, NULL, 0, &required) == 0);
			CHECK(required == length);
			exact = malloc(required);
			CHECK(exact != NULL);
			CHECK(ieee80211_encode_hecap(&cap, exact, required, &n) == 0);
			CHECK(n == required);
			CHECK(memcmp(exact, expected, n) == 0);
			CHECK(ieee80211_parse_hecap(exact, n, &parsed) == 0);
			CHECK(parsed.has_he);
			free(exact);
			for (i = 0; i < required; i++)
				reject(&cap, i, EMSGSIZE);
		}
	}
	file = fopen(argv[1], "r");
	CHECK(file != NULL);
	n = 0;
	while (fscanf(file, "%2x", &byte) == 1) {
		CHECK(n < sizeof(fixture));
		fixture[n++] = (uint8_t)byte;
	}
	fclose(file);
	CHECK(n == 37);
	CHECK(ieee80211_parse_hecap(fixture, n, &cap) == 0);
	CHECK(ieee80211_encode_hecap(&cap, encoded, sizeof(encoded), &length) == 0);
	CHECK(length == n);
	CHECK(memcmp(encoded, fixture, n) == 0);
	printf("PASS: %u bounded HE encoding checks; no frame transmission.\n", checks);
	return (0);
}
