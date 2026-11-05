/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2017 Adrian Chadd <adrian@FreeBSD.org>
 * Copyright (c) 2026 Denis Lemire
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/errno.h>
#ifdef _KERNEL
#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_media.h>
#include <net/ethernet.h>
#else
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#endif

#include <net80211/ieee80211.h>
#ifdef _KERNEL
#include <net80211/ieee80211_var.h>
#endif
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

/*
 * Adapt the existing BSD VHT map intersection to HE's matching two-bit
 * encoding.  Inputs and result are host order.  Pair one endpoint's TX
 * map with the other endpoint's RX map, not two same-direction maps.
 */
uint16_t
ieee80211_he_mcs_intersect(uint16_t tx, uint16_t rx)
{
	uint16_t result;
	unsigned int i, a, b, value;

	result = 0;
	for (i = 0; i < 8; i++) {
		a = (tx >> (2 * i)) & 3;
		b = (rx >> (2 * i)) & 3;
		if (a == IEEE80211_HE_MCS_NOT_SUPPORTED ||
		    b == IEEE80211_HE_MCS_NOT_SUPPORTED)
			value = IEEE80211_HE_MCS_NOT_SUPPORTED;
		else
			value = MIN(a, b);
		result |= value << (2 * i);
	}
	return (result);
}

int
ieee80211_parse_heoper(const uint8_t *ie, size_t len,
    struct ieee80211_he_operation *out)
{
	size_t ie_len, needed;
	uint32_t params;

	if (out == NULL)
		return (EINVAL);
	memset(out, 0, sizeof(*out));
	if (ie == NULL)
		return (EINVAL);
	if (len < 3)
		return (EMSGSIZE);
	if (ie[0] != IEEE80211_ELEMID_EXTFIELD ||
	    ie[2] != IEEE80211_ELEMID_EXT_HE_OPER)
		return (EINVAL);
	ie_len = (size_t)ie[1] + 2;
	needed = 3 + sizeof(*out);
	if (ie_len > len || ie_len < needed)
		return (EMSGSIZE);
	params = (uint32_t)ie[3] | ((uint32_t)ie[4] << 8) |
	    ((uint32_t)ie[5] << 16);
	/* Optional field flags/lengths match the native ifconfig HE decoder. */
	if (params & (1U << 14))
		needed += 3;	/* VHT operation information */
	if (params & (1U << 15))
		needed += 1;	/* Max Co-Hosted BSSID Indicator */
	if (params & (1U << 17))
		needed += 5;	/* 6 GHz operation information */
	if (ie_len < needed)
		return (EMSGSIZE);
	memcpy(out, ie + 3, sizeof(*out));
	return (0);
}

bool
ieee80211_he_mcs_supports_basic(uint16_t supported, uint16_t basic)
{
	unsigned int i, have, need;

	for (i = 0; i < 8; i++) {
		need = (basic >> (2 * i)) & 3;
		/* In a basic set, 3 means this NSS is not required. */
		if (need == 3)
			continue;
		have = (supported >> (2 * i)) & 3;
		if (have == IEEE80211_HE_MCS_NOT_SUPPORTED || have < need)
			return (false);
	}
	return (true);
}

#ifdef _KERNEL
CTASSERT(offsetof(struct ieee80211com, ic_spare) -
    offsetof(struct ieee80211com, ic_get_hecap) == sizeof(uint64_t));

int
ieee80211_get_hecap(struct ieee80211vap *vap,
    const struct ieee80211_channel *chan, struct net80211_he_cap *out)
{
	struct ieee80211com *ic;
	int error;

	if (out == NULL)
		return (EINVAL);
	memset(out, 0, sizeof(*out));
	if (vap == NULL || vap->iv_ic == NULL || chan == NULL ||
	    chan == IEEE80211_CHAN_ANYC)
		return (EINVAL);
	ic = vap->iv_ic;
	if (ic->ic_get_hecap == NULL)
		return (ENOTSUP);
	error = ic->ic_get_hecap(vap, chan, out);
	if (error == 0 && !out->has_he)
		error = ENOTSUP;
	if (error != 0)
		memset(out, 0, sizeof(*out));
	return (error);
}

static size_t
he_ie_available(const struct ieee80211_ies *ies, const uint8_t *ie)
{
	uintptr_t offset;

	if (ie == NULL || ies->data == NULL || ies->len <= 0 ||
	    (uintptr_t)ie < (uintptr_t)ies->data)
		return (0);
	offset = (uintptr_t)ie - (uintptr_t)ies->data;
	if (offset > (size_t)ies->len)
		return (0);
	return ((size_t)ies->len - offset);
}

/*
 * Construct a 5 GHz station candidate, in the peer's RX/TX perspective.
 * This validates metadata and rate constraints only.  It does not establish
 * that HE was advertised or negotiated, and changes no node/driver flags.
 */
int
ieee80211_he_prepare_peer(struct ieee80211_node *ni,
    struct net80211_he_cap *peer, struct ieee80211_he_operation *oper)
{
	struct net80211_he_cap local;
	uint16_t peer_rx, peer_tx, basic;
	int error;

	if (peer == NULL || oper == NULL)
		return (EINVAL);
	memset(peer, 0, sizeof(*peer));
	memset(oper, 0, sizeof(*oper));
	if (ni == NULL || ni->ni_vap == NULL || ni->ni_chan == NULL ||
	    ni->ni_chan == IEEE80211_CHAN_ANYC)
		return (EINVAL);
	if (ni->ni_vap->iv_opmode != IEEE80211_M_STA ||
	    !IEEE80211_IS_CHAN_5GHZ(ni->ni_chan))
		return (ENOTSUP);
	error = ieee80211_get_hecap(ni->ni_vap, ni->ni_chan, &local);
	if (error != 0)
		return (error);
	if (ni->ni_ies.hecap_ie == NULL || ni->ni_ies.heoper_ie == NULL)
		return (ENOENT);
	error = ieee80211_parse_hecap(ni->ni_ies.hecap_ie,
	    he_ie_available(&ni->ni_ies, ni->ni_ies.hecap_ie), peer);
	if (error != 0)
		goto fail;
	error = ieee80211_parse_heoper(ni->ni_ies.heoper_ie,
	    he_ie_available(&ni->ni_ies, ni->ni_ies.heoper_ie), oper);
	if (error != 0)
		goto fail;
	peer_rx = ieee80211_he_mcs_intersect(
	    le16toh(local.he_mcs_nss_supp.tx_mcs_80),
	    le16toh(peer->he_mcs_nss_supp.rx_mcs_80));
	peer_tx = ieee80211_he_mcs_intersect(
	    le16toh(peer->he_mcs_nss_supp.tx_mcs_80),
	    le16toh(local.he_mcs_nss_supp.rx_mcs_80));
	basic = le16toh(oper->he_mcs_nss_set);
	if ((peer_rx & 3) == IEEE80211_HE_MCS_NOT_SUPPORTED ||
	    (peer_tx & 3) == IEEE80211_HE_MCS_NOT_SUPPORTED ||
	    !ieee80211_he_mcs_supports_basic(peer_rx, basic) ||
	    !ieee80211_he_mcs_supports_basic(peer_tx, basic)) {
		error = ENOTSUP;
		goto fail;
	}
	peer->he_mcs_nss_supp.rx_mcs_80 = htole16(peer_rx);
	peer->he_mcs_nss_supp.tx_mcs_80 = htole16(peer_tx);
	/* Limit the initial candidate to bandwidths at or below 80 MHz. */
	peer->he_cap_elem.phy_cap_info[0] &=
	    ~(IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G |
	    IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G);
	peer->he_mcs_nss_supp.rx_mcs_160 = 0xffff;
	peer->he_mcs_nss_supp.tx_mcs_160 = 0xffff;
	peer->he_mcs_nss_supp.rx_mcs_80p80 = 0xffff;
	peer->he_mcs_nss_supp.tx_mcs_80p80 = 0xffff;
	return (0);
fail:
	memset(peer, 0, sizeof(*peer));
	memset(oper, 0, sizeof(*oper));
	return (error);
}
#endif
