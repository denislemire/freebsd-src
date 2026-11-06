/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Denis Lemire. */
/* Exercise the actual helper against modeled queue/lock/completion APIs. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned int u_int;
#define NQ 17
#define MAX_FRAMES (NQ * 8)
#define nitems(a) (sizeof(a) / sizeof((a)[0]))
struct ieee80211_key_conf { unsigned tag; };
struct ieee80211_tx_info { struct { struct ieee80211_key_conf *hw_key; } control; };
struct sk_buff { struct sk_buff *next, *prev; struct ieee80211_tx_info info; unsigned id; };
struct sk_buff_head { struct sk_buff sentinel; unsigned count; };
struct lkpi_txq { struct sk_buff_head skbq; bool locked; };
struct ieee80211_sta { struct lkpi_txq *txq[NQ]; };
struct lkpi_sta { struct ieee80211_sta sta; };
struct mock_wiphy { bool held; };
struct ieee80211_hw { struct mock_wiphy *wiphy; };
static unsigned active_locks, completions, node_refs;
static bool expected_drop[MAX_FRAMES], completed[MAX_FRAMES];
static struct lkpi_sta *active_sta;
static struct ieee80211_key_conf *retiring_key;
#define lockdep_assert_wiphy(w) assert((w)->held)
#define LSTA_TO_STA(s) (&(s)->sta)
#define TXQ_TO_LTXQ(q) (q)
#define IEEE80211_SKB_CB(s) (&(s)->info)
#define LKPI_80211_LTXQ_LOCK(q) do { assert(!(q)->locked); (q)->locked = true; active_locks++; } while (0)
#define LKPI_80211_LTXQ_UNLOCK(q) do { assert((q)->locked); (q)->locked = false; active_locks--; } while (0)
#define skb_queue_walk_safe(q, p, t) \
    for ((p) = (q)->sentinel.next, (t) = (p)->next; \
        (p) != &(q)->sentinel; (p) = (t), (t) = (p)->next)
static void
skb_unlink(struct sk_buff *skb, struct sk_buff_head *q)
{
    assert(((struct lkpi_txq *)q)->locked);
    skb->prev->next = skb->next;
    skb->next->prev = skb->prev;
    skb->next = skb->prev = NULL;
    assert(q->count > 0); q->count--;
}
static void
ieee80211_free_txskb(struct ieee80211_hw *hw, struct sk_buff *skb)
{
    assert(hw->wiphy->held && active_locks == 0 && node_refs > 1);
    assert(expected_drop[skb->id] && !completed[skb->id]);
    /* All references in the modeled queues must be unlinked before callbacks. */
    for (unsigned q = 0; q < NQ; q++) {
        if (!active_sta->sta.txq[q]) continue;
        for (struct sk_buff *s = active_sta->sta.txq[q]->skbq.sentinel.next;
            s != &active_sta->sta.txq[q]->skbq.sentinel; s = s->next)
            assert(s->info.control.hw_key != retiring_key);
    }
    completed[skb->id] = true; completions++; node_refs--;
    free(skb);
}
#include "generated_key_retirement_under_test.h"
static void
append(struct lkpi_txq *q, struct sk_buff *s)
{
    s->prev = q->skbq.sentinel.prev; s->next = &q->skbq.sentinel;
    s->prev->next = s; q->skbq.sentinel.prev = s; q->skbq.count++;
}
int
main(void)
{
    unsigned long total_dropped = 0, total_survived = 0;
    for (unsigned seed = 0; seed < 4101; seed++) {
        struct mock_wiphy wiphy = { .held = true };
        struct ieee80211_hw hw = { .wiphy = &wiphy };
        struct ieee80211_key_conf old = { 1 }, other = { 2 };
        struct lkpi_sta lsta = { 0 };
        struct lkpi_txq queues[NQ] = { 0 };
        for (unsigned q = 0; q < NQ; q++) {
            queues[q].skbq.sentinel.next = &queues[q].skbq.sentinel;
            queues[q].skbq.sentinel.prev = &queues[q].skbq.sentinel;
        }
        unsigned survivor_ids[NQ][8], survivor_count[NQ] = { 0 };
        unsigned id = 0, want_drop = 0;
        uint32_t rng = seed + 1;
        memset(expected_drop, 0, sizeof(expected_drop));
        memset(completed, 0, sizeof(completed));
        active_locks = completions = 0; node_refs = 1;
        active_sta = &lsta; retiring_key = &old;
        for (unsigned q = 0; q < NQ; q++) {
            if (seed == 4096 || (seed + q) % 5 == 0) continue;
            lsta.sta.txq[q] = &queues[q];
            for (unsigned i = 0; i < (seed == 4097 ? 0 : (seed + q * 3) % 9); i++) {
                struct sk_buff *s = calloc(1, sizeof(*s)); assert(s);
                rng = rng * UINT32_C(1664525) + UINT32_C(1013904223);
                unsigned kind = seed == 4098 ? 1 : seed == 4099 ? 0 : seed == 4100 ? 2 : rng >> 30;
                s->id = id++;
                s->info.control.hw_key = kind == 0 ? NULL : kind == 1 ? &other : &old;
                expected_drop[s->id] = s->info.control.hw_key == &old;
                if (expected_drop[s->id]) want_drop++;
                else survivor_ids[q][survivor_count[q]++] = s->id;
                append(&queues[q], s); node_refs++;
            }
        }
        assert(lkpi_discard_key_txq(&hw, &lsta, &old) == want_drop);
        assert(completions == want_drop && active_locks == 0);
        for (unsigned q = 0; q < NQ; q++) {
            struct sk_buff *sentinel = &queues[q].skbq.sentinel;
            struct sk_buff *s = sentinel->next, *prev = sentinel;
            assert(queues[q].skbq.count == survivor_count[q]);
            for (unsigned i = 0; i < survivor_count[q]; i++) {
                assert(s && s->id == survivor_ids[q][i] && !completed[s->id]);
                assert(s->prev == prev); prev = s; s = s->next;
            }
            assert(s == sentinel && sentinel->prev == prev);
            s = sentinel->next;
            while (s != sentinel) { struct sk_buff *next = s->next; free(s); node_refs--; s = next; total_survived++; }
        }
        for (unsigned i = 0; i < id; i++) assert(completed[i] == expected_drop[i]);
        assert(node_refs == 1); total_dropped += completions;
    }
    printf("4101 modeled circular-sentinel queue cases passed; dropped %lu, preserved %lu; completion outside queue locks.\n", total_dropped, total_survived);
    return 0;
}
