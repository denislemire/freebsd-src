/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Denis Lemire. */
#include <sys/param.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_he.h>

static unsigned int checks, allocations, releases, malformed;
static bool fail_allocation;
#define CHECK(x) do { checks++; assert(x); } while (0)

static void *
test_alloc(size_t len)
{
	if (fail_allocation) {
		fail_allocation = false;
		return (NULL);
	}
	allocations++;
	return (calloc(1, len));
}

static void
test_free(void *p)
{
	releases++;
	free(p);
}

#define IEEE80211_MALLOC(len, type, flags) test_alloc(len)
#define IEEE80211_FREE(ptr, type) test_free(ptr)
#define net80211_printf(...) ((void)malformed++)

/* Vendor IEs are not exercised by this HE ownership suite. */
static int iswpaoui(const uint8_t *ie) { (void)ie; return (0); }
static int iswmeoui(const uint8_t *ie) { (void)ie; return (0); }

#include "generated_ies_under_test.h"

static void
destroy(struct ieee80211_ies *ies)
{
	ieee80211_ies_cleanup(ies);
	CHECK(ies->hecap_ie == NULL);
	CHECK(ies->heoper_ie == NULL);
	/* The existing cleanup API frees the blob but does not zero data/len.
	 * Model destruction of its enclosing owner, not reuse of freed storage. */
	memset(ies, 0, sizeof(*ies));
}

int
main(int argc, char **argv)
{
	struct ieee80211_ies scan = {0}, node = {0};
	struct net80211_he_cap cap;
	uint8_t fixture[256], operation[9], frame[512], *original, *allocation;
	size_t len = 0;
	unsigned int byte, saved;
	FILE *file;

	CHECK(argc == 3);
	file = fopen(argv[1], "r");
	CHECK(file != NULL);
	while (fscanf(file, "%2x", &byte) == 1) {
		CHECK(len < sizeof(fixture));
		fixture[len++] = (uint8_t)byte;
	}
	fclose(file);
	CHECK(len == 37);
	file = fopen(argv[2], "r");
	CHECK(file != NULL);
	for (size_t i = 0; i < sizeof(operation); i++) {
		CHECK(fscanf(file, "%2x", &byte) == 1);
		operation[i] = (uint8_t)byte;
	}
	fclose(file);
	CHECK(sizeof(scan) == sizeof(struct baseline_ieee80211_ies));
	CHECK(offsetof(struct ieee80211_ies, data) ==
	    offsetof(struct baseline_ieee80211_ies, data));
	CHECK(offsetof(struct ieee80211_ies, len) ==
	    offsetof(struct baseline_ieee80211_ies, len));

	/* Ownership: invalidate the original receive buffer after copying. */
	original = malloc(len);
	CHECK(original != NULL);
	memcpy(original, fixture, len);
	CHECK(ieee80211_ies_init(&scan, original, (int)len) == 1);
	CHECK(scan.hecap_ie == NULL);
	memset(original, 0xa5, len);
	free(original);
	ieee80211_ies_expand(&scan);
	CHECK(scan.hecap_ie == scan.data);
	CHECK(memcmp(scan.hecap_ie, fixture, len) == 0);
	CHECK(ieee80211_parse_hecap(scan.hecap_ie, len, &cap) == 0);
	CHECK(cap.has_he);

	/* Relocation: node view points into its own copy, not the scan cache. */
	CHECK(ieee80211_ies_init(&node, scan.data, scan.len) == 1);
	ieee80211_ies_expand(&node);
	CHECK(node.hecap_ie == node.data);
	CHECK(node.hecap_ie != scan.hecap_ie);
	destroy(&scan);
	CHECK(memcmp(node.hecap_ie, fixture, len) == 0);

	/* Same-size replacement reuses allocation but cannot retain HE. */
	allocation = node.data;
	memset(frame, 0, len);
	frame[0] = IEEE80211_ELEMID_SSID;
	frame[1] = (uint8_t)(len - 2);
	CHECK(ieee80211_ies_init(&node, frame, (int)len) == 1);
	CHECK(node.data == allocation);
	CHECK(node.hecap_ie == NULL);
	ieee80211_ies_expand(&node);
	CHECK(node.hecap_ie == NULL);

	/* Grow, then replace with a shorter blob without HE. */
	memcpy(frame, fixture, len);
	frame[len] = IEEE80211_ELEMID_RATES;
	frame[len + 1] = 0;
	CHECK(ieee80211_ies_init(&node, frame, (int)len + 2) == 1);
	ieee80211_ies_expand(&node);
	CHECK(node.hecap_ie == node.data);
	CHECK(ieee80211_ies_init(&node, frame + len, 2) == 1);
	CHECK(node.hecap_ie == NULL);
	ieee80211_ies_expand(&node);
	CHECK(node.hecap_ie == NULL);

	/* Last recognized HE occurrence wins; malformed HE clears the view. */
	memcpy(frame, fixture, len);
	frame[len] = IEEE80211_ELEMID_EXTFIELD;
	frame[len + 1] = 1;
	frame[len + 2] = IEEE80211_ELEMID_EXT_HE_CAPA;
	CHECK(ieee80211_ies_init(&node, frame, (int)len + 3) == 1);
	ieee80211_ies_expand(&node);
	CHECK(node.hecap_ie == NULL);
	frame[len + 2] = IEEE80211_ELEMID_EXT_HE_OPER;
	CHECK(ieee80211_ies_init(&node, frame, (int)len + 3) == 1);
	ieee80211_ies_expand(&node);
	CHECK(node.hecap_ie == node.data);

	/* An outer TLV overrun also invalidates the HE view, without reading it. */
	saved = malformed;
	frame[len + 1] = 255;
	CHECK(ieee80211_ies_init(&node, frame, (int)len + 3) == 1);
	ieee80211_ies_expand(&node);
	CHECK(malformed == saved + 1);
	CHECK(node.hecap_ie == NULL);

	/* Allocation failure after a length change leaves no stale HE view. */
	CHECK(ieee80211_ies_init(&node, fixture, (int)len) == 1);
	ieee80211_ies_expand(&node);
	CHECK(node.hecap_ie != NULL);
	fail_allocation = true;
	CHECK(ieee80211_ies_init(&node, frame, (int)len + 3) == 0);
	CHECK(node.data == NULL && node.len == 0 && node.hecap_ie == NULL);
	destroy(&node);

	/* HE Operation follows the same owned-copy and fail-closed rules. */
	memcpy(frame, fixture, len);
	memcpy(frame + len, operation, sizeof(operation));
	CHECK(ieee80211_ies_init(&node, frame, (int)len + 9) == 1);
	ieee80211_ies_expand(&node);
	CHECK(node.hecap_ie == node.data);
	CHECK(node.heoper_ie == node.data + len);
	CHECK(memcmp(node.heoper_ie, operation, sizeof(operation)) == 0);
	frame[len + 9] = IEEE80211_ELEMID_EXTFIELD;
	frame[len + 10] = 1;
	frame[len + 11] = IEEE80211_ELEMID_EXT_HE_OPER;
	CHECK(ieee80211_ies_init(&node, frame, (int)len + 12) == 1);
	ieee80211_ies_expand(&node);
	CHECK(node.hecap_ie == node.data && node.heoper_ie == NULL);
	CHECK(ieee80211_ies_init(&node, operation, 9) == 1);
	ieee80211_ies_expand(&node);
	CHECK(node.hecap_ie == NULL && node.heoper_ie == node.data);
	destroy(&node);
	CHECK(allocations == releases);
	printf("PASS: %u HE ownership checks; %u allocations, %u releases.\n",
	    checks, allocations, releases);
	return (0);
}
