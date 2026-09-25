// Host unit tests for the per-client 4-way pairing matcher in pwnpal-marauder/pwnpal_frames.h
// (Phase B). Pure logic, no hardware. See tests/run.sh.
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "../pwnpal-marauder/pwnpal_frames.h"

static int failures = 0;
#define CHECK(cond, name)                \
    do {                                 \
        if(cond) {                       \
            printf("  ok   %s\n", name); \
        } else {                         \
            printf("  FAIL %s\n", name); \
            failures++;                  \
        }                                \
    } while(0)

#define N 32
#define WIN 300

static void reset(PwnpalHsHalf* t) {
    for(int i = 0; i < N; i++) t[i].used = false;
}
static void cli(uint8_t* c, uint8_t tag) {
    for(int i = 0; i < 6; i++) c[i] = tag;
}
static void rep(uint8_t* r, uint8_t tag) {
    memset(r, 0, 8);
    r[7] = tag;
}

int main(void) {
    PwnpalHsHalf t[N];
    uint8_t cA[6], cB[6], r1[8], r2[8];
    cli(cA, 0xA1); cli(cB, 0xB2); rep(r1, 1); rep(r2, 2);

    printf("pwnpal_hs_insert_match:\n");

    reset(t);
    CHECK(!pwnpal_hs_insert_match(t, N, 5, cA, r1, true, 1000, WIN), "M1 first -> no match yet");
    CHECK(pwnpal_hs_insert_match(t, N, 5, cA, r1, false, 1100, WIN), "M2 same ap/client/replay in window -> match");

    reset(t);
    pwnpal_hs_insert_match(t, N, 5, cA, r1, true, 1000, WIN);
    CHECK(!pwnpal_hs_insert_match(t, N, 5, cB, r1, false, 1100, WIN), "M2 from a different client -> no match");

    reset(t);
    pwnpal_hs_insert_match(t, N, 5, cA, r1, true, 1000, WIN);
    CHECK(!pwnpal_hs_insert_match(t, N, 5, cA, r2, false, 1100, WIN), "M2 with a different replay -> no match");

    reset(t);
    pwnpal_hs_insert_match(t, N, 5, cA, r1, true, 1000, WIN);
    CHECK(!pwnpal_hs_insert_match(t, N, 5, cA, r1, false, 1000 + WIN + 1, WIN), "M2 outside the window -> no match");

    reset(t);
    CHECK(!pwnpal_hs_insert_match(t, N, 5, cA, r1, false, 1000, WIN), "M2 first -> stored, no match");
    CHECK(pwnpal_hs_insert_match(t, N, 5, cA, r1, true, 1100, WIN), "M1 completes an earlier M2");

    reset(t);
    pwnpal_hs_insert_match(t, N, 5, cA, r1, true, 1000, WIN);
    CHECK(pwnpal_hs_insert_match(t, N, 5, cA, r1, false, 1100, WIN), "pair completes");
    CHECK(!pwnpal_hs_insert_match(t, N, 5, cA, r1, false, 1150, WIN), "second M2 alone -> no re-match (halves cleared)");

    reset(t);
    pwnpal_hs_insert_match(t, N, 5, cA, r1, true, 1000, WIN); // same ap/client/kind twice
    pwnpal_hs_insert_match(t, N, 5, cA, r1, true, 1050, WIN); // -> refresh, not a 2nd slot
    int used = 0;
    for(int i = 0; i < N; i++)
        if(t[i].used) used++;
    CHECK(used == 1, "same ap/client/kind upserts one slot, not two");

    // table full -> evicts the oldest. Fill all N with distinct M1 halves (never match each other),
    // then a new one evicts ms=1000; that evicted client's M2 must not complete.
    reset(t);
    for(int i = 0; i < N; i++) {
        uint8_t c[6];
        cli(c, (uint8_t)(i + 1));
        pwnpal_hs_insert_match(t, N, 5, c, r1, true, 1000 + i, WIN);
    }
    uint8_t cNew[6];
    cli(cNew, 0xFF);
    pwnpal_hs_insert_match(t, N, 5, cNew, r1, true, 5000, WIN); // evicts oldest (ms=1000, client 1)
    uint8_t cOldest[6];
    cli(cOldest, 1);
    CHECK(!pwnpal_hs_insert_match(t, N, 5, cOldest, r1, false, 5050, WIN), "evicted-oldest client -> M2 finds no M1");
    CHECK(pwnpal_hs_insert_match(t, N, 5, cNew, r1, false, 5050, WIN), "newest client still pairs");

    printf("%s (%d failures)\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
