/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Denis Lemire. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "generated_bitrate_under_test.h"

static unsigned checks;

static void
expect(struct rate_info *r, uint32_t value)
{
	assert(linuxkpi_cfg80211_calculate_bitrate(r) == value);
	checks++;
}

int
main(void)
{
	static const uint8_t widths[] = {
		RATE_INFO_BW_20, RATE_INFO_BW_40, RATE_INFO_BW_80,
		RATE_INFO_BW_160, RATE_INFO_BW_HE_RU
	};
	static const uint8_t full_widths[] = {
		RATE_INFO_BW_20, RATE_INFO_BW_40, RATE_INFO_BW_80,
		RATE_INFO_BW_160
	};
	static const uint8_t matching_ru[] = {
		NL80211_RATE_INFO_HE_RU_ALLOC_242,
		NL80211_RATE_INFO_HE_RU_ALLOC_484,
		NL80211_RATE_INFO_HE_RU_ALLOC_996,
		NL80211_RATE_INFO_HE_RU_ALLOC_2x996
	};
	static const uint16_t published_20mhz[] = {
		86, 172, 258, 344, 516, 688, 774, 860, 1032, 1147, 1290, 1434
	};
	static const uint16_t ru_mcs0[] = { 9, 18, 38, 86, 172, 360, 721 };
	struct rate_info r = { .flags = RATE_INFO_FLAGS_HE_MCS, .nss = 1 };
	uint32_t last, current, full;
	unsigned bw, gi, mcs, nss, ru, dcm, i;

	/* Published HE rate spot checks, rounded to tenths of a Mbit/s. */
	expect(&r, 86);                         /* 20MHz MCS0, 0.8us GI. */
	r.mcs = 11;
	expect(&r, 1434);
	r.nss = 2;
	r.bw = RATE_INFO_BW_40;
	expect(&r, 5735);
	r.he_gi = NL80211_RATE_INFO_HE_GI_1_6;
	expect(&r, 5417);
	r.he_gi = NL80211_RATE_INFO_HE_GI_3_2;
	expect(&r, 4875);
	r.he_gi = 0;
	r.bw = RATE_INFO_BW_80;
	expect(&r, 12010);
	r.bw = RATE_INFO_BW_160;
	r.nss = 8;
	expect(&r, 96078);
	for (mcs = 0; mcs < 12; mcs++) {
		r = (struct rate_info){ .flags = RATE_INFO_FLAGS_HE_MCS,
		    .nss = 1, .mcs = mcs, .legacy = 540 };
		expect(&r, published_20mhz[mcs]);
	}
	for (ru = 0; ru < 7; ru++) {
		r = (struct rate_info){ .flags = RATE_INFO_FLAGS_HE_MCS,
		    .nss = 1, .bw = RATE_INFO_BW_HE_RU, .he_ru_alloc = ru };
		expect(&r, ru_mcs0[ru]);
	}

	/* Full channel and its same-size RU must agree over the whole domain. */
	for (i = 0; i < 4; i++)
	for (gi = 0; gi < 3; gi++)
	for (nss = 1; nss <= 8; nss++)
	for (mcs = 0; mcs <= 11; mcs++) {
		r = (struct rate_info){ .flags = RATE_INFO_FLAGS_HE_MCS,
		    .bw = full_widths[i], .he_gi = gi, .nss = nss, .mcs = mcs };
		full = linuxkpi_cfg80211_calculate_bitrate(&r);
		r.bw = RATE_INFO_BW_HE_RU;
		r.he_ru_alloc = matching_ru[i];
		expect(&r, full);
	}

	/* Every supported width/RU: rate rises with MCS/NSS, falls with GI. */
	for (bw = 0; bw < sizeof(widths); bw++)
	for (ru = 0; ru < 7; ru++)
	for (gi = 0; gi < 3; gi++)
	for (nss = 1; nss <= 8; nss++) {
		last = 0;
		for (mcs = 0; mcs <= 11; mcs++) {
			r = (struct rate_info){ .flags = RATE_INFO_FLAGS_HE_MCS,
			    .bw = widths[bw], .he_ru_alloc = ru, .he_gi = gi,
			    .nss = nss, .mcs = mcs };
			current = linuxkpi_cfg80211_calculate_bitrate(&r);
			assert(current > last && current <= 96078);
			checks++;
			last = current;
			if (nss < 8) {
				r.nss++;
				assert(linuxkpi_cfg80211_calculate_bitrate(&r) > current);
				checks++;
				r.nss--;
			}
			if (gi < 2) {
				r.he_gi++;
				assert(linuxkpi_cfg80211_calculate_bitrate(&r) <= current);
				checks++;
			}
		}
	}

	/* DCM domain, malformed fields and dispatch boundaries. */
	for (mcs = 0; mcs < 256; mcs++)
	for (nss = 0; nss < 10; nss++)
	for (gi = 0; gi < 4; gi++)
	for (dcm = 0; dcm < 3; dcm++) {
		r = (struct rate_info){ .flags = RATE_INFO_FLAGS_HE_MCS,
		    .nss = nss, .mcs = mcs, .he_gi = gi, .he_dcm = dcm };
		if (mcs > 11 || nss == 0 || nss > 8 || gi > 2 || dcm > 1 ||
		    (dcm && (nss > 2 || (mcs != 0 && mcs != 1 &&
		    mcs != 3 && mcs != 4))))
			expect(&r, 0);
		else {
			assert(linuxkpi_cfg80211_calculate_bitrate(&r) > 0);
			checks++;
		}
	}
	r = (struct rate_info){ .flags = RATE_INFO_FLAGS_HE_MCS, .nss = 1,
	    .he_dcm = 1 };
	expect(&r, 43);
	r.mcs = 4;
	expect(&r, 258);
	r.he_dcm = 0;
	r.bw = RATE_INFO_BW_HE_RU;
	r.he_ru_alloc = 255;
	expect(&r, 0);
	r.he_ru_alloc = 7;
	expect(&r, 0);
	r.bw = RATE_INFO_BW_5;
	expect(&r, 0);
	r.bw = RATE_INFO_BW_10;
	expect(&r, 0);
	r.bw = RATE_INFO_BW_320;
	expect(&r, 0);
	r.bw = 255;
	expect(&r, 0);
	r = (struct rate_info){ .legacy = 540 };
	expect(&r, 540);
	r.flags = RATE_INFO_FLAGS_MCS;
	expect(&r, 111111);
	r.flags = RATE_INFO_FLAGS_VHT_MCS;
	expect(&r, 222222);
	printf("HE bitrate: %u checks passed\n", checks);
	return (0);
}
