/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Denis Lemire. */
/* Fuzz actual native helpers; these invariants do not certify wire semantics. */
#include <sys/types.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_he.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct net80211_he_cap cap, decoded, zero_cap = {0};
	struct ieee80211_he_operation oper, zero_oper = {0};
	uint8_t encoded[IEEE80211_HE_CAP_IE_MAX], before[sizeof(encoded)];
	size_t required, written, capacity;
	int error;

	memset(&cap, 0xa5, sizeof(cap));
	error = ieee80211_parse_hecap(data, size, &cap);
	if (error != 0) {
		assert(memcmp(&cap, &zero_cap, sizeof(cap)) == 0);
	} else {
		assert(cap.has_he);
		required = SIZE_MAX;
		error = ieee80211_encode_hecap(&cap, NULL, 0, &required);
		if (error == 0) {
			assert(required <= sizeof(encoded));
			written = SIZE_MAX;
			assert(ieee80211_encode_hecap(&cap, encoded,
			    sizeof(encoded), &written) == 0);
			assert(written == required);
			assert(ieee80211_parse_hecap(encoded, written,
			    &decoded) == 0);
			assert(memcmp(&cap, &decoded, sizeof(cap)) == 0);
			/* A short destination must be left entirely untouched. */
			capacity = size ? data[0] % required : 0;
			memset(encoded, 0xa5, sizeof(encoded));
			memcpy(before, encoded, sizeof(before));
			written = SIZE_MAX;
			assert(ieee80211_encode_hecap(&cap, encoded,
			    capacity, &written) != 0);
			assert(written == 0);
			assert(memcmp(encoded, before, sizeof(encoded)) == 0);
		} else {
			assert(required == 0);
		}
	}
	memset(&oper, 0xa5, sizeof(oper));
	if (ieee80211_parse_heoper(data, size, &oper) != 0)
		assert(memcmp(&oper, &zero_oper, sizeof(oper)) == 0);
	return (0);
}
