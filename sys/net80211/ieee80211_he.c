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
#include <sys/malloc.h>
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

/* Serialize only fields whose presence is advertised by the PHY flags. */
int
ieee80211_encode_hecap(const struct net80211_he_cap *cap, uint8_t *ie,
    size_t len, size_t *written)
{
	uint8_t encoded[3 + sizeof(cap->he_cap_elem) +
	    sizeof(cap->he_mcs_nss_supp) + sizeof(cap->ppe_thres)];
	const uint8_t *maps;
	size_t n, ppe_len;
	unsigned int i, nss, nrus, ru_mask;
	uint8_t widths;

	if (written == NULL)
		return (EINVAL);
	*written = 0;
	if (cap == NULL || (ie == NULL && len != 0))
		return (EINVAL);
	if (!cap->has_he)
		return (ENOTSUP);
	/* NSS 1 must be supported in both mandatory <=80 MHz maps. */
	maps = (const uint8_t *)&cap->he_mcs_nss_supp;
	if ((maps[0] & 3) == IEEE80211_HE_MCS_NOT_SUPPORTED ||
	    (maps[2] & 3) == IEEE80211_HE_MCS_NOT_SUPPORTED)
		return (EINVAL);
	encoded[0] = IEEE80211_ELEMID_EXTFIELD;
	encoded[2] = IEEE80211_ELEMID_EXT_HE_CAPA;
	memcpy(encoded + 3, &cap->he_cap_elem, sizeof(cap->he_cap_elem));
	n = 3 + sizeof(cap->he_cap_elem);
	memcpy(encoded + n, maps, 4);
	n += 4;
	widths = cap->he_cap_elem.phy_cap_info[0];
	if (widths & IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G) {
		memcpy(encoded + n, &cap->he_mcs_nss_supp.rx_mcs_160, 4);
		n += 4;
	}
	if (widths &
	    IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G) {
		memcpy(encoded + n, &cap->he_mcs_nss_supp.rx_mcs_80p80, 4);
		n += 4;
	}
	if (cap->he_cap_elem.phy_cap_info[6] &
	    IEEE80211_HE_PHY_CAP6_PPE_THRESHOLD_PRESENT) {
		nss = (cap->ppe_thres[0] & 7) + 1;
		ru_mask = (cap->ppe_thres[0] >> 3) & 15;
		nrus = 0;
		for (i = 0; i < 4; i++)
			nrus += (ru_mask >> i) & 1;
		/* An outgoing PPE field must describe at least one RU. */
		if (nrus == 0)
			return (EINVAL);
		ppe_len = (7 + nss * nrus * 6 + 7) / 8;
		if (ppe_len > sizeof(cap->ppe_thres))
			return (EINVAL);
		memcpy(encoded + n, cap->ppe_thres, ppe_len);
		n += ppe_len;
	}
	encoded[1] = n - 2;
	if (ie == NULL) {
		*written = n;
		return (0);
	}
	if (len < n)
		return (EMSGSIZE);
	memcpy(ie, encoded, n);
	*written = n;
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
CTASSERT(offsetof(struct ieee80211_node, ni_spare) -
    offsetof(struct ieee80211_node, ni_he) == sizeof(uint64_t));
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
static void
he_state_reset(struct ieee80211_he_state *state)
{

	memset(&state->local, 0, sizeof(state->local));
	memset(&state->peer, 0, sizeof(state->peer));
	memset(&state->oper, 0, sizeof(state->oper));
	state->freq = 0;
	state->advertised = state->negotiated = false;
}

void
ieee80211_he_node_cleanup(struct ieee80211_node *ni)
{

	ni->ni_flags &= ~IEEE80211_NODE_HE;
	if (ni->ni_he != NULL) {
		mtx_lock(&ni->ni_he->lock);
		he_state_reset(ni->ni_he);
		mtx_unlock(&ni->ni_he->lock);
	}
}

/* Keep storage across association cleanup; free it on final node release. */
void
ieee80211_he_node_free(struct ieee80211_node *ni)
{

	if (ni->ni_he != NULL) {
		mtx_destroy(&ni->ni_he->lock);
		IEEE80211_FREE(ni->ni_he, M_80211_NODE);
		ni->ni_he = NULL;
	}
}

int
ieee80211_he_get_state(struct ieee80211_node *ni,
    struct ieee80211_he_state *out)
{
	struct ieee80211_he_state *state;
	int error;

	memset(out, 0, sizeof(*out));
	state = ni->ni_he;
	if (state == NULL)
		return (ENOENT);
	mtx_lock(&state->lock);
	error = ENOENT;
	if ((ni->ni_flags & IEEE80211_NODE_HE) && state->negotiated) {
		out->local = state->local;
		out->peer = state->peer;
		out->oper = state->oper;
		out->freq = state->freq;
		out->advertised = state->advertised;
		out->negotiated = state->negotiated;
		error = 0;
	}
	mtx_unlock(&state->lock);
	return (error);
}

bool
ieee80211_he_was_advertised(struct ieee80211_node *ni)
{
	bool advertised;

	if (ni->ni_he == NULL)
		return (false);
	mtx_lock(&ni->ni_he->lock);
	advertised = ni->ni_he->advertised;
	mtx_unlock(&ni->ni_he->lock);
	return (advertised);
}

void
ieee80211_he_request_advertised(struct ieee80211_node *ni)
{

	KASSERT(ni->ni_he != NULL, ("HE request without prepared state"));
	mtx_lock(&ni->ni_he->lock);
	ni->ni_he->advertised = true;
	mtx_unlock(&ni->ni_he->lock);
}

/* Initial native policy: no host HTC, TWT, BSR, OMI or OPS procedures. */
static void
he_sta_policy(struct net80211_he_cap *cap)
{
	uint8_t *mac;

	mac = cap->he_cap_elem.mac_cap_info;
	mac[0] = 0;
	/* Retain the hardware's required trigger processing padding. */
	mac[1] &= IEEE80211_HE_MAC_CAP1_TF_MAC_PAD_DUR_MASK;
	mac[2] = 0;
	mac[3] = 0;
	mac[4] &= IEEE80211_HE_MAC_CAP4_AMSDU_IN_AMPDU;
	mac[5] &= IEEE80211_HE_MAC_CAP5_HT_VHT_TRIG_FRAME_RX;
	cap->he_cap_elem.phy_cap_info[0] &=
	    IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G;
	cap->he_mcs_nss_supp.rx_mcs_160 = 0xffff;
	cap->he_mcs_nss_supp.tx_mcs_160 = 0xffff;
	cap->he_mcs_nss_supp.rx_mcs_80p80 = 0xffff;
	cap->he_mcs_nss_supp.tx_mcs_80p80 = 0xffff;
}

int
ieee80211_he_prepare_request(struct ieee80211_node *ni, uint8_t *ie,
    size_t len, size_t *written)
{
	struct net80211_he_cap local, peer;
	struct ieee80211_he_operation oper;
	struct ieee80211_he_state *state;
	uint8_t encoded[IEEE80211_HE_CAP_IE_MAX];
	size_t n;
	int error;

	if (written == NULL)
		return (EINVAL);
	*written = 0;
	if (ni == NULL || ni->ni_vap == NULL || ie == NULL)
		return (EINVAL);
	ieee80211_he_node_cleanup(ni);
	if (!(ni->ni_vap->iv_flags_ext & IEEE80211_FEXT_HE) ||
	    !(ni->ni_vap->iv_flags_ht & IEEE80211_FHT_HT) ||
	    !(ni->ni_vap->iv_vht_flags & IEEE80211_FVHT_VHT) ||
	    ni->ni_ies.wme_ie == NULL || ni->ni_ies.htcap_ie == NULL ||
	    ni->ni_ies.vhtcap_ie == NULL)
		return (ENOTSUP);
	/* Require a valid HE AP and compatible basic MCS before advertising. */
	error = ieee80211_he_prepare_peer(ni, &peer, &oper);
	if (error != 0)
		return (error);
	error = ieee80211_get_hecap(ni->ni_vap, ni->ni_chan, &local);
	if (error != 0)
		return (error);
	if (IEEE80211_IS_CHAN_VHT160(ni->ni_chan) ||
	    IEEE80211_IS_CHAN_VHT80P80(ni->ni_chan))
		return (ENOTSUP);
	he_sta_policy(&local);
	error = ieee80211_encode_hecap(&local, encoded, sizeof(encoded), &n);
	if (error != 0)
		return (error);
	if (n > len)
		return (EMSGSIZE);
	state = ni->ni_he;
	if (state == NULL) {
		state = IEEE80211_MALLOC(sizeof(*state), M_80211_NODE,
		    IEEE80211_M_NOWAIT | IEEE80211_M_ZERO);
		if (state == NULL)
			return (ENOMEM);
		mtx_init(&state->lock, "80211 HE state", NULL, MTX_DEF);
		ni->ni_he = state;
	}
	mtx_lock(&state->lock);
	state->local = local;
	state->freq = ni->ni_chan->ic_freq;
	mtx_unlock(&state->lock);
	memcpy(ie, encoded, n);
	*written = n;
	return (0);
}

int
ieee80211_he_accept_response(struct ieee80211_node *ni,
    const uint8_t *cap_ie, size_t cap_len, const uint8_t *oper_ie,
    size_t oper_len)
{
	struct ieee80211_he_state *state;
	struct net80211_he_cap peer;
	struct ieee80211_he_operation oper;
	uint16_t rx, tx, basic;
	int error;

	ni->ni_flags &= ~IEEE80211_NODE_HE;
	state = ni->ni_he;
	if (state == NULL)
		return (0);
	mtx_lock(&state->lock);
	error = 0;
	if (!state->advertised)
		goto out;
	state->negotiated = false;
	memset(&state->peer, 0, sizeof(state->peer));
	memset(&state->oper, 0, sizeof(state->oper));
	if (cap_ie == NULL && oper_ie == NULL) {
		he_state_reset(state);
		goto out;
	}
	if (ni->ni_chan == NULL || ni->ni_chan == IEEE80211_CHAN_ANYC ||
	    ni->ni_chan->ic_freq != state->freq ||
	    !(ni->ni_flags & IEEE80211_NODE_QOS) ||
	    !(ni->ni_flags & IEEE80211_NODE_HT) ||
	    !(ni->ni_flags & IEEE80211_NODE_VHT)) {
		error = EINVAL;
		goto out;
	}
	error = ieee80211_parse_hecap(cap_ie, cap_len, &peer);
	if (error != 0)
		goto out;
	error = ieee80211_parse_heoper(oper_ie, oper_len, &oper);
	if (error != 0)
		goto out;
	rx = ieee80211_he_mcs_intersect(
	    le16toh(state->local.he_mcs_nss_supp.tx_mcs_80),
	    le16toh(peer.he_mcs_nss_supp.rx_mcs_80));
	tx = ieee80211_he_mcs_intersect(
	    le16toh(peer.he_mcs_nss_supp.tx_mcs_80),
	    le16toh(state->local.he_mcs_nss_supp.rx_mcs_80));
	basic = le16toh(oper.he_mcs_nss_set);
	if ((rx & 3) == IEEE80211_HE_MCS_NOT_SUPPORTED ||
	    (tx & 3) == IEEE80211_HE_MCS_NOT_SUPPORTED ||
	    !ieee80211_he_mcs_supports_basic(rx, basic) ||
	    !ieee80211_he_mcs_supports_basic(tx, basic)) {
		error = ENOTSUP;
		goto out;
	}
	peer.he_mcs_nss_supp.rx_mcs_80 = htole16(rx);
	peer.he_mcs_nss_supp.tx_mcs_80 = htole16(tx);
	peer.he_cap_elem.phy_cap_info[0] &=
	    IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G;
	peer.he_mcs_nss_supp.rx_mcs_160 = 0xffff;
	peer.he_mcs_nss_supp.tx_mcs_160 = 0xffff;
	peer.he_mcs_nss_supp.rx_mcs_80p80 = 0xffff;
	peer.he_mcs_nss_supp.tx_mcs_80p80 = 0xffff;
	state->peer = peer;
	state->oper = oper;
	state->negotiated = true;
	ni->ni_flags |= IEEE80211_NODE_HE;
	error = 0;
out:
	mtx_unlock(&state->lock);
	return (error);
}
int
ieee80211_he_update_operation(struct ieee80211_node *ni,
    const uint8_t *ie, size_t len)
{
	struct ieee80211_he_operation oper;
	struct ieee80211_he_state *state;
	uint16_t basic;
	int error;

	state = ni->ni_he;
	if (state == NULL)
		return (0);
	mtx_lock(&state->lock);
	error = 0;
	if (!state->negotiated)
		goto out;
	error = ieee80211_parse_heoper(ie, len, &oper);
	if (error != 0)
		goto out;
	basic = le16toh(oper.he_mcs_nss_set);
	if (!ieee80211_he_mcs_supports_basic(
	    le16toh(state->peer.he_mcs_nss_supp.rx_mcs_80), basic) ||
	    !ieee80211_he_mcs_supports_basic(
	    le16toh(state->peer.he_mcs_nss_supp.tx_mcs_80), basic)) {
		error = ENOTSUP;
		goto out;
	}
	state->oper = oper;
	error = 0;
out:
	mtx_unlock(&state->lock);
	return (error);
}
#endif
