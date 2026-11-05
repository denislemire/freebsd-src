/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026, Denis Lemire
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/errno.h>
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <stdbool.h>
#include <string.h>
#endif

#include <net80211/ieee80211.h>
#include <net80211/ieee80211_he.h>

int
ieee80211_parse_hecap(const uint8_t *ie, size_t len,
    struct net80211_he_cap *out)
{
	struct net80211_he_cap cap;
	const uint8_t *pos, *end;
	size_t ie_len, mcs_len, ppe_len;
	unsigned int i, nss, nrus, ru_mask;
	uint8_t widths;

	if (out == NULL)
		return (EINVAL);
	memset(out, 0, sizeof(*out));
	if (ie == NULL)
		return (EINVAL);
	if (len < 3)
		return (EMSGSIZE);
	if (ie[0] != IEEE80211_ELEMID_EXTFIELD ||
	    ie[2] != IEEE80211_ELEMID_EXT_HE_CAPA)
		return (EINVAL);
	ie_len = (size_t)ie[1] + 2;
	if (ie_len > len || ie_len < 3 + sizeof(cap.he_cap_elem) + 4)
		return (EMSGSIZE);

	memset(&cap, 0, sizeof(cap));
	memset(&cap.he_mcs_nss_supp, 0xff, sizeof(cap.he_mcs_nss_supp));
	memcpy(&cap.he_cap_elem, ie + 3, sizeof(cap.he_cap_elem));
	widths = cap.he_cap_elem.phy_cap_info[0];
	mcs_len = 4;
	if (widths & IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G)
		mcs_len += 4;
	if (widths & IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G)
		mcs_len += 4;
	pos = ie + 3 + sizeof(cap.he_cap_elem);
	end = ie + ie_len;
	if ((size_t)(end - pos) < mcs_len)
		return (EMSGSIZE);

	/* Copy each compact wire tuple into its normalized bandwidth slot. */
	memcpy(&cap.he_mcs_nss_supp.rx_mcs_80, pos, 4);
	pos += 4;
	if (widths & IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G) {
		memcpy(&cap.he_mcs_nss_supp.rx_mcs_160, pos, 4);
		pos += 4;
	}
	if (widths &
	    IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G) {
		memcpy(&cap.he_mcs_nss_supp.rx_mcs_80p80, pos, 4);
		pos += 4;
	}

	if (cap.he_cap_elem.phy_cap_info[6] &
	    IEEE80211_HE_PHY_CAP6_PPE_THRESHOLD_PRESENT) {
		if (pos == end)
			return (EMSGSIZE);
		/* 7 header bits, then two 3-bit thresholds per NSS/RU pair. */
		nss = (pos[0] & 7) + 1;
		ru_mask = (pos[0] >> 3) & 15;
		nrus = 0;
		for (i = 0; i < 4; i++)
			nrus += (ru_mask >> i) & 1;
		ppe_len = (7 + nss * nrus * 6 + 7) / 8;
		if (ppe_len > sizeof(cap.ppe_thres) ||
		    (size_t)(end - pos) < ppe_len)
			return (EMSGSIZE);
		memcpy(cap.ppe_thres, pos, ppe_len);
	}
	cap.has_he = true;
	*out = cap;
	return (0);
}
