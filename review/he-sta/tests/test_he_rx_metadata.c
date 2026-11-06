/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Denis Lemire. */
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "generated_rx_metadata_under_test.h"

#define SAME(member) _Static_assert(offsetof(struct ieee80211_rx_stats, member) == \
    offsetof(struct ieee80211_rx_stats_baseline, member), #member " moved")
SAME(r_flags); SAME(c_pktflags); SAME(c_rx_tsf);
SAME(c_nf_ctl); SAME(c_nf_ext); SAME(c_rssi_ctl); SAME(c_rssi_ext);
SAME(c_nf); SAME(c_rssi); SAME(c_chain); SAME(c_rate);
SAME(c_freq); SAME(c_ieee); SAME(c_width); SAME(c_band);
SAME(evm); SAME(c_phytype); SAME(c_vhtnss); SAME(c_pad2);
_Static_assert(sizeof(struct ieee80211_rx_stats) ==
    sizeof(struct ieee80211_rx_stats_baseline), "RX stats size changed");
_Static_assert(offsetof(struct ieee80211_rx_stats, c_henss) ==
    offsetof(struct ieee80211_rx_stats_baseline, c_vhtnss), "HE NSS offset");
_Static_assert(offsetof(struct ieee80211_rx_stats, c_hegi) ==
    offsetof(struct ieee80211_rx_stats_baseline, c_pad2), "HE GI offset");
_Static_assert(offsetof(struct ieee80211_rx_stats, c_heru) ==
    offsetof(struct ieee80211_rx_stats_baseline, c_pad2) + 1, "HE RU offset");

int
main(void)
{
	struct ieee80211_rx_status in;
	struct ieee80211_rx_stats out;
	unsigned gi, ru, mcs, nss, dcm, width, checks = 0;

	for (gi = 0; gi < 4; gi++)
	for (ru = 0; ru < 8; ru++)
	for (mcs = 0; mcs < 12; mcs++)
	for (nss = 1; nss <= 8; nss++)
	for (dcm = 0; dcm < 2; dcm++)
	for (width = 0; width < 2; width++) {
		memset(&in, 0, sizeof(in));
		in.bw = width ? RATE_INFO_BW_HE_RU : RATE_INFO_BW_40;
		in.he_gi = gi;
		in.he_ru = ru;
		in.rate_idx = mcs;
		in.nss = nss;
		in.he_dcm = dcm;
		memset(&out, 0, sizeof(out));
		out.r_flags = 0x12345678;
		out.c_nf = -96;
		out.c_rssi = 42;
		out.c_rx_tsf = 0x123456789abcdefULL;
		out.c_pktflags = IEEE80211_RX_F_DECRYPTED | IEEE80211_RX_F_LDPC;
		lkpi_convert_he_rx_stats(&in, &out);
		assert(out.c_pktflags == (IEEE80211_RX_F_DECRYPTED |
		    IEEE80211_RX_F_LDPC | IEEE80211_RX_F_HE |
		    (dcm ? IEEE80211_RX_F_HE_DCM : 0)));
		assert(out.c_rate == mcs && out.c_henss == nss);
		assert(out.c_hegi == (gi < 3 ? gi : IEEE80211_RX_HE_GI_UNKNOWN));
		assert(out.c_heru == (width && ru < 7 ? ru :
		    IEEE80211_RX_HE_RU_UNKNOWN));
		assert(out.r_flags == 0x12345678 && out.c_nf == -96 && out.c_rssi == 42);
		assert(out.c_rx_tsf == 0x123456789abcdefULL);
		assert(out.c_vhtnss == out.c_henss);
		assert(out.c_pad2[0] == out.c_hegi && out.c_pad2[1] == out.c_heru);
		checks += 8;
	}
	printf("HE RX metadata: %u checks passed; native RX stats size %zu\n",
	    checks, sizeof(out));
	return (0);
}
