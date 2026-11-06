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
reject(const uint8_t *ie, size_t len, int error)
{
	struct ieee80211_he_operation out, zero = {0};

	memset(&out, 0xa5, sizeof(out));
	CHECK(ieee80211_parse_heoper(ie, len, &out) == error);
	CHECK(memcmp(&out, &zero, sizeof(out)) == 0);
}

int
main(int argc, char **argv)
{
	/* Independent wire lengths: fixed IE is 9 bytes; VHT adds 3,
	 * co-hosted indicator adds 1, and 6 GHz information adds 5. */
	static const size_t lengths[8] = {9, 12, 10, 13, 14, 17, 15, 18};
	struct ieee80211_he_operation out;
	uint8_t fixture[9], frame[19], *prefix, *fixed;
	size_t n, cut, i;
	unsigned int options, byte;
	FILE *file;

	CHECK(argc == 2);
	CHECK(sizeof(out) == 6);
	file = fopen(argv[1], "r");
	CHECK(file != NULL);
	n = 0;
	while (fscanf(file, "%2x", &byte) == 1) {
		CHECK(n < sizeof(fixture));
		fixture[n++] = (uint8_t)byte;
	}
	fclose(file);
	CHECK(n == 9);
	CHECK(ieee80211_parse_heoper(fixture, n, &out) == 0);
	CHECK(memcmp(&out, fixture + 3, sizeof(out)) == 0);
	fixed = (uint8_t *)&out;
	CHECK(fixed[0] == 0xf4 && fixed[1] == 0x3f && fixed[2] == 0);
	CHECK((fixed[3] & 0x3f) == 33);
	CHECK(((unsigned int)fixed[4] | ((unsigned int)fixed[5] << 8)) == 0xfffc);

	for (options = 0; options < 8; options++) {
		n = lengths[options];
		memcpy(frame, fixture, sizeof(fixture));
		for (i = sizeof(fixture); i < sizeof(frame); i++)
			frame[i] = (uint8_t)(0xb0 + i);
		frame[1] = (uint8_t)(n - 2);
		if (options & 1)
			frame[4] |= 0x40;
		if (options & 2)
			frame[4] |= 0x80;
		if (options & 4)
			frame[5] |= 0x02;
		CHECK(ieee80211_parse_heoper(frame, n, &out) == 0);
		CHECK(memcmp(&out, frame + 3, sizeof(out)) == 0);
		for (cut = 0; cut < n; cut++) {
			prefix = malloc(cut == 0 ? 1 : cut);
			CHECK(prefix != NULL);
			memcpy(prefix, frame, cut);
			reject(prefix, cut, EMSGSIZE);
			if (cut >= 2) {
				prefix[1] = (uint8_t)(cut - 2);
				reject(prefix, cut, EMSGSIZE);
			}
			free(prefix);
		}
	}
	reject(NULL, 0, EINVAL);
	CHECK(ieee80211_parse_heoper(fixture, sizeof(fixture), NULL) == EINVAL);
	memcpy(frame, fixture, sizeof(fixture));
	frame[0] = IEEE80211_ELEMID_VENDOR;
	reject(frame, sizeof(fixture), EINVAL);
	frame[0] = IEEE80211_ELEMID_EXTFIELD;
	frame[2] = IEEE80211_ELEMID_EXT_HE_CAPA;
	reject(frame, sizeof(fixture), EINVAL);
	memcpy(frame, fixture, sizeof(fixture));
	frame[9] = 0xa5;
	CHECK(ieee80211_parse_heoper(frame, 10, &out) == 0);
	frame[1] = 8;
	CHECK(ieee80211_parse_heoper(frame, 10, &out) == 0);
	printf("PASS: %u HE Operation checks over 8 optional-field layouts.\n", checks);
	printf("Captured operation: 9 bytes, color 33, basic MCS/NSS 0xfffc.\n");
	return (0);
}
