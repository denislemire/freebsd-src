/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Denis Lemire. */
#include <sys/param.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define le16toh OSSwapLittleToHostInt16
#define htole16 OSSwapHostToLittleInt16
#else
#include <sys/endian.h>
#endif
#include <net80211/ieee80211.h>
#include <net80211/_ieee80211.h>
#include <net80211/ieee80211_he.h>

static unsigned int checks, malformed;
#define CHECK(x) do { checks++; assert(x); } while (0)
static int fail_alloc;
static void *test_alloc(size_t len) { return (fail_alloc ? NULL : calloc(1, len)); }
#define IEEE80211_MALLOC(len, type, flags) test_alloc(len)
#define IEEE80211_FREE(ptr, type) free(ptr)
#define net80211_printf(...) ((void)malformed++)
static int iswpaoui(const uint8_t *ie) { (void)ie; return (0); }
static int iswmeoui(const uint8_t *ie) { (void)ie; return (0); }
#include "generated_ies_under_test.h"

/* Minimal field models isolate protocol logic. They are not ABI models;
 * the kernel build/layout assertion and live probes validate the real types. */
struct ieee80211vap;
struct ieee80211com {
	int (*ic_get_hecap)(struct ieee80211vap *,
	    const struct ieee80211_channel *, struct net80211_he_cap *);
};
struct ieee80211vap {
	struct ieee80211com *iv_ic;
	enum ieee80211_opmode iv_opmode;
	unsigned int iv_flags_ext, iv_flags_ht;
	uint64_t iv_vht_flags;
};
struct ieee80211_node {
	struct ieee80211vap *ni_vap;
	struct ieee80211_channel *ni_chan;
	struct ieee80211_ies ni_ies;
	struct ieee80211_he_state *ni_he;
	unsigned int ni_flags;
};
/* Kernel mutexes are modeled as no-ops here; live build/probes cover real types. */
#define mtx_init(...) ((void)0)
#define mtx_lock(...) ((void)0)
#define mtx_unlock(...) ((void)0)
#define mtx_destroy(...) ((void)0)
#define KASSERT(x, msg) assert(x)
#include "generated_he_peer_under_test.h"

static struct net80211_he_cap local;
static int hardware_error;
static unsigned int hardware_calls;

static int
hardware_cap(struct ieee80211vap *vap, const struct ieee80211_channel *chan,
    struct net80211_he_cap *out)
{
	(void)vap;
	(void)chan;
	hardware_calls++;
	*out = local;
	return (hardware_error);
}

static size_t
fixture(const char *path, uint8_t *out, size_t limit)
{
	FILE *file = fopen(path, "r");
	unsigned int byte;
	size_t n = 0;

	CHECK(file != NULL);
	while (fscanf(file, "%2x", &byte) == 1) {
		CHECK(n < limit);
		out[n++] = (uint8_t)byte;
	}
	fclose(file);
	return (n);
}

static void
failed(struct ieee80211_node *ni, int error)
{
	struct net80211_he_cap peer, zero = {0};
	struct ieee80211_he_operation op, zero_op = {0};

	memset(&peer, 0xa5, sizeof(peer));
	memset(&op, 0xa5, sizeof(op));
	CHECK(ieee80211_he_prepare_peer(ni, &peer, &op) == error);
	CHECK(memcmp(&peer, &zero, sizeof(peer)) == 0);
	CHECK(memcmp(&op, &zero_op, sizeof(op)) == 0);
}

static void
test_transaction(struct ieee80211_node *ni, uint8_t *frame,
    size_t cap_len, size_t op_len)
{
	struct ieee80211vap *vap = ni->ni_vap;
	uint8_t encoded[57], saved[64], *prefix;
	uint8_t dummy[2] = {0};
	struct net80211_he_cap saved_local = local;
	struct ieee80211_he_state snapshot;
	uint16_t freq = ni->ni_chan->ic_freq;
	size_t n, cut;

	memcpy(saved, frame, cap_len + op_len);
	memcpy(local.he_cap_elem.mac_cap_info, "\x01\x08\x0a\x10\x60\x80", 6);
	ni->ni_ies.wme_ie = ni->ni_ies.htcap_ie = ni->ni_ies.vhtcap_ie = dummy;
	vap->iv_flags_ht = IEEE80211_FHT_HT;
	vap->iv_vht_flags = IEEE80211_FVHT_VHT;
	ni->ni_flags = IEEE80211_NODE_QOS | IEEE80211_NODE_HT | IEEE80211_NODE_VHT;
	CHECK(ieee80211_he_prepare_request(ni, encoded, sizeof(encoded), &n) == ENOTSUP);
	CHECK(n == 0 && ni->ni_he == NULL);
	vap->iv_flags_ext = IEEE80211_FEXT_HE;
	CHECK(ieee80211_he_prepare_request(ni, encoded, 23, &n) == EMSGSIZE);
	CHECK(n == 0 && ni->ni_he == NULL);
	fail_alloc = 1;
	CHECK(ieee80211_he_prepare_request(ni, encoded, sizeof(encoded), &n) == ENOMEM);
	CHECK(n == 0 && ni->ni_he == NULL);
	fail_alloc = 0;
	CHECK(ieee80211_he_prepare_request(ni, encoded, sizeof(encoded), &n) == 0);
	CHECK(n == 24 && ni->ni_he != NULL);
	CHECK(memcmp(encoded + 3, "\x00\x08\x00\x00\x40\x80", 6) == 0);
	CHECK(!ni->ni_he->advertised && !ni->ni_he->negotiated);
	CHECK(ieee80211_he_accept_response(ni, frame, cap_len, frame + cap_len, op_len) == 0);
	CHECK(!ni->ni_he->negotiated && !(ni->ni_flags & IEEE80211_NODE_HE));
	ieee80211_he_request_advertised(ni);
	CHECK(ieee80211_he_was_advertised(ni));
	for (cut = 0; cut < cap_len; cut++) {
		prefix = malloc(cut == 0 ? 1 : cut);
		CHECK(prefix != NULL);
		memcpy(prefix, frame, cut);
		CHECK(ieee80211_he_accept_response(ni, prefix, cut, frame + cap_len, op_len) != 0);
		CHECK(!ni->ni_he->negotiated && !(ni->ni_flags & IEEE80211_NODE_HE));
		free(prefix);
	}
	for (cut = 0; cut < op_len; cut++) {
		prefix = malloc(cut == 0 ? 1 : cut);
		CHECK(prefix != NULL);
		memcpy(prefix, frame + cap_len, cut);
		CHECK(ieee80211_he_accept_response(ni, frame, cap_len, prefix, cut) != 0);
		CHECK(!ni->ni_he->negotiated && !(ni->ni_flags & IEEE80211_NODE_HE));
		free(prefix);
	}
	CHECK(ieee80211_he_accept_response(ni, frame, cap_len, frame + cap_len, op_len) == 0);
	CHECK(ni->ni_he->negotiated && (ni->ni_flags & IEEE80211_NODE_HE));
	CHECK(ieee80211_he_get_state(ni, &snapshot) == 0);
	CHECK(snapshot.negotiated && snapshot.advertised);
	CHECK(le16toh(ni->ni_he->peer.he_mcs_nss_supp.rx_mcs_80) == 0xfffa);
	CHECK(le16toh(ni->ni_he->peer.he_mcs_nss_supp.tx_mcs_80) == 0xfffa);
	memset(frame, 0, cap_len + op_len);
	CHECK(ni->ni_he->peer.has_he);
	CHECK(le16toh(ni->ni_he->oper.he_mcs_nss_set) == 0xfffc);
	memcpy(frame, saved, cap_len + op_len);
	frame[cap_len + 6] = 34;
	CHECK(ieee80211_he_update_operation(ni, frame + cap_len, op_len) == 0);
	CHECK(((uint8_t *)&ni->ni_he->oper)[3] == 34);
	frame[cap_len + 7] = 0xc0;
	CHECK(ieee80211_he_update_operation(ni, frame + cap_len, op_len) == ENOTSUP);
	CHECK(((uint8_t *)&ni->ni_he->oper)[3] == 34);
	memcpy(frame, saved, cap_len + op_len);
	ni->ni_chan->ic_freq = freq + 20;
	CHECK(ieee80211_he_accept_response(ni, frame, cap_len, frame + cap_len, op_len) == EINVAL);
	CHECK(!ni->ni_he->negotiated && !(ni->ni_flags & IEEE80211_NODE_HE));
	ni->ni_chan->ic_freq = freq;
	CHECK(ieee80211_he_accept_response(ni, frame, cap_len, NULL, 0) == EINVAL);
	ni->ni_flags &= ~IEEE80211_NODE_QOS;
	CHECK(ieee80211_he_accept_response(ni, frame, cap_len, frame + cap_len, op_len) == EINVAL);
	ni->ni_flags |= IEEE80211_NODE_QOS;
	CHECK(ieee80211_he_accept_response(ni, NULL, 0, NULL, 0) == 0);
	CHECK(ni->ni_he != NULL && !ni->ni_he->negotiated &&
	    !(ni->ni_flags & IEEE80211_NODE_HE));
	CHECK(ieee80211_he_prepare_request(ni, encoded, sizeof(encoded), &n) == 0);
	ieee80211_he_node_cleanup(ni);
	ieee80211_he_node_cleanup(ni);
	CHECK(ieee80211_he_get_state(ni, &snapshot) == ENOENT);
	ieee80211_he_node_free(ni);
	CHECK(ni->ni_he == NULL && !(ni->ni_flags & IEEE80211_NODE_HE));
	ni->ni_ies.wme_ie = ni->ni_ies.htcap_ie = ni->ni_ies.vhtcap_ie = NULL;
	vap->iv_flags_ext = vap->iv_flags_ht = 0;
	vap->iv_vht_flags = 0;
	local = saved_local;
}

int
main(int argc, char **argv)
{
	struct ieee80211com ic = { .ic_get_hecap = hardware_cap };
	struct ieee80211vap vap = { .iv_ic = &ic, .iv_opmode = IEEE80211_M_STA };
	struct ieee80211_channel chan = { .ic_flags = IEEE80211_CHAN_5GHZ };
	struct ieee80211_node ni = { .ni_vap = &vap, .ni_chan = &chan };
	struct net80211_he_cap peer;
	struct ieee80211_he_operation op;
	uint8_t frame[64], original[64];
	size_t cap_len, op_len, len;
	unsigned int calls;

	CHECK(argc == 3);
	cap_len = fixture(argv[1], frame, sizeof(frame));
	op_len = fixture(argv[2], frame + cap_len, sizeof(frame) - cap_len);
	len = cap_len + op_len;
	CHECK(cap_len == 37 && op_len == 9);
	memcpy(original, frame, len);
	local.has_he = true;
	local.he_cap_elem.phy_cap_info[0] =
	    IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G;
	memset(&local.he_mcs_nss_supp, 0xff, sizeof(local.he_mcs_nss_supp));
	local.he_mcs_nss_supp.rx_mcs_80 = htole16(0xfffa);
	local.he_mcs_nss_supp.tx_mcs_80 = htole16(0xfffa);
	CHECK(ieee80211_ies_init(&ni.ni_ies, frame, (int)len) == 1);
	ieee80211_ies_expand(&ni.ni_ies);
	CHECK(ieee80211_he_prepare_peer(&ni, &peer, &op) == 0);
	CHECK(peer.has_he);
	CHECK(le16toh(peer.he_mcs_nss_supp.rx_mcs_80) == 0xfffa);
	CHECK(le16toh(peer.he_mcs_nss_supp.tx_mcs_80) == 0xfffa);
	CHECK(le16toh(peer.he_mcs_nss_supp.rx_mcs_160) == 0xffff);
	CHECK(le16toh(peer.he_mcs_nss_supp.tx_mcs_80p80) == 0xffff);
	CHECK(le16toh(op.he_mcs_nss_set) == 0xfffc);

	test_transaction(&ni, frame, cap_len, op_len);

	/* Actual preparation must pair opposite directions, not just its helper. */
	local.he_mcs_nss_supp.tx_mcs_80 = htole16(0xfffe);
	CHECK(ieee80211_he_prepare_peer(&ni, &peer, &op) == 0);
	CHECK(le16toh(peer.he_mcs_nss_supp.rx_mcs_80) == 0xfffe);
	CHECK(le16toh(peer.he_mcs_nss_supp.tx_mcs_80) == 0xfffa);
	local.he_mcs_nss_supp.tx_mcs_80 = htole16(0xffff);
	failed(&ni, ENOTSUP);
	local.he_mcs_nss_supp.tx_mcs_80 = htole16(0xfffa);
	hardware_error = EIO;
	failed(&ni, EIO);
	hardware_error = 0;
	local.has_he = false;
	failed(&ni, ENOTSUP);
	local.has_he = true;
	ic.ic_get_hecap = NULL;
	failed(&ni, ENOTSUP);
	ic.ic_get_hecap = hardware_cap;
	calls = hardware_calls;
	ni.ni_chan = IEEE80211_CHAN_ANYC;
	failed(&ni, EINVAL);
	CHECK(hardware_calls == calls);
	ni.ni_chan = &chan;
	chan.ic_flags = IEEE80211_CHAN_2GHZ;
	failed(&ni, ENOTSUP);
	chan.ic_flags = IEEE80211_CHAN_5GHZ;
	vap.iv_opmode = IEEE80211_M_HOSTAP;
	failed(&ni, ENOTSUP);
	vap.iv_opmode = IEEE80211_M_STA;
	failed(NULL, EINVAL);

	/* Require three streams in the BSS basic set; synthetic local has two. */
	frame[cap_len + 7] = 0xc0;
	CHECK(ieee80211_ies_init(&ni.ni_ies, frame, (int)len) == 1);
	ieee80211_ies_expand(&ni.ni_ies);
	failed(&ni, ENOTSUP);
	memcpy(frame, original, len);
	CHECK(ieee80211_ies_init(&ni.ni_ies, frame, (int)cap_len) == 1);
	ieee80211_ies_expand(&ni.ni_ies);
	failed(&ni, ENOENT);
	CHECK(ieee80211_ies_init(&ni.ni_ies, frame, (int)len) == 1);
	ieee80211_ies_expand(&ni.ni_ies);
	ni.ni_ies.hecap_ie = (uint8_t *)((uintptr_t)ni.ni_ies.data + len + 1);
	failed(&ni, EMSGSIZE);
	ieee80211_ies_cleanup(&ni.ni_ies);
	CHECK(ni.ni_ies.hecap_ie == NULL && ni.ni_ies.heoper_ie == NULL);
	printf("PASS: %u native HE peer-preparation checks; no driver activation.\n", checks);
	return (0);
}
