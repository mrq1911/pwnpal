// Host unit tests for the passive Flock/ALPR matcher in pwnpal-marauder/pwnpal_frames.h.
// Pure logic, no hardware. See tests/run.sh.
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

static const uint8_t FLOCK_OUI[3] = {0x70, 0xc9, 0x4e}; // a known Flock prefix
static const uint8_t RAND_OUI[3] = {0x11, 0x22, 0x33};  // not Flock

static void setmac(uint8_t* m, const uint8_t* oui, uint8_t tail) {
    m[0] = oui[0]; m[1] = oui[1]; m[2] = oui[2];
    m[3] = 0xAB; m[4] = 0xCD; m[5] = tail;
}

// Beacon (subtype 8): FC@0, addr1@4, addr2@10, addr3@16, 12-byte fixed params @24, IEs @36.
static int mk_beacon(uint8_t* b, const uint8_t* a2oui, const uint8_t* a3oui, const char* ssid) {
    memset(b, 0, 256);
    b[0] = 0x80;
    memset(b + 4, 0xff, 6); // addr1 broadcast
    setmac(b + 10, a2oui, 0x01);
    setmac(b + 16, a3oui, 0x01);
    int p = 36;
    b[p++] = 0; // SSID tag
    int sl = ssid ? (int)strlen(ssid) : 0;
    b[p++] = (uint8_t)sl;
    for(int i = 0; i < sl; i++) b[p++] = (uint8_t)ssid[i];
    return p;
}

// Probe request (subtype 4): FC@0, addrs, IEs @24 (no fixed params).
static void put_ie(uint8_t* b, int* p, uint8_t tag, const uint8_t* val, int vlen) {
    b[(*p)++] = tag;
    b[(*p)++] = (uint8_t)vlen;
    for(int i = 0; i < vlen; i++) b[(*p)++] = val[i];
}

static int mk_probe_ie(uint8_t* b, const uint8_t* a2oui, bool good_payload) {
    memset(b, 0, 256);
    b[0] = 0x40; // probe request
    memset(b + 4, 0xff, 6);
    setmac(b + 10, a2oui, 0x02);
    memset(b + 16, 0xff, 6);
    static const uint8_t liteon[] = {0x50, 0x6f, 0x9a, 0x16, 0x03, 0x01, 0x03};
    static const uint8_t wpa[] = {0x00, 0x50, 0xf2, 0x08, 0x00, 0x00, 0x00};
    static const uint8_t bad[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00};
    static const uint8_t rates[] = {0x02, 0x04, 0x0b, 0x16};
    int p = 24;
    put_ie(b, &p, 0, nullptr, 0);                 // wildcard SSID
    put_ie(b, &p, 2, rates, 4);                    // supported rates
    put_ie(b, &p, 12, rates, 2);                   // DS/whatever (tag-only match)
    put_ie(b, &p, 127, rates, 2);                  // extended caps
    put_ie(b, &p, 221, good_payload ? liteon : bad, 7);
    put_ie(b, &p, 45, rates, 2);                   // HT caps
    put_ie(b, &p, 191, rates, 2);                  // VHT caps
    put_ie(b, &p, 221, wpa, 7);
    return p;
}

int main(void) {
    uint8_t b[256];
    const uint8_t* dev;
    int len;

    printf("pwnpal_oui_is_flock:\n");
    uint8_t m[6];
    setmac(m, FLOCK_OUI, 0);
    CHECK(pwnpal_oui_is_flock(m), "known Flock OUI matches");
    setmac(m, RAND_OUI, 0);
    CHECK(!pwnpal_oui_is_flock(m), "random OUI does not match");

    printf("pwnpal_ssid_is_flock:\n");
    CHECK(pwnpal_ssid_is_flock("flock"), "flock");
    CHECK(pwnpal_ssid_is_flock("FLOCK_cam3"), "case-insensitive + substring");
    CHECK(pwnpal_ssid_is_flock("test_flck"), "flck substring");
    CHECK(!pwnpal_ssid_is_flock("linksys"), "normal SSID negative");
    CHECK(pwnpal_ssid_is_flock("flocking_birds"), "contains flock -> positive");

    printf("beacon detection:\n");
    len = mk_beacon(b, RAND_OUI, RAND_OUI, "Flock_Safety_A1");
    CHECK(pwnpal_flock_match(b, len, &dev) == FLOCK_SSID, "SSID keyword -> FLOCK_SSID");
    len = mk_beacon(b, FLOCK_OUI, RAND_OUI, "linksys");
    CHECK(pwnpal_flock_match(b, len, &dev) == FLOCK_OUI_ADDR2, "flock OUI as transmitter");
    len = mk_beacon(b, RAND_OUI, FLOCK_OUI, "");
    CHECK(pwnpal_flock_match(b, len, &dev) == FLOCK_HIDDEN_OUI, "hidden SSID + flock BSSID");
    len = mk_beacon(b, RAND_OUI, RAND_OUI, "coffeeshop");
    CHECK(pwnpal_flock_match(b, len, &dev) == FLOCK_NONE, "ordinary AP -> none");

    printf("probe-request IE fingerprint:\n");
    len = mk_probe_ie(b, RAND_OUI, true); // randomized MAC, but the IE shape gives it away
    CHECK(pwnpal_flock_match(b, len, &dev) == FLOCK_PROBE_IE, "IE fingerprint beats MAC randomization");
    len = mk_probe_ie(b, RAND_OUI, false); // wrong vendor payload
    CHECK(pwnpal_flock_match(b, len, &dev) != FLOCK_PROBE_IE, "wrong vendor payload -> not IE-sig");
    len = mk_probe_ie(b, FLOCK_OUI, false); // no IE-sig but known OUI + wildcard
    CHECK(pwnpal_flock_match(b, len, &dev) == FLOCK_PROBE_OUI, "known OUI wildcard probe");

    printf("guards:\n");
    len = mk_beacon(b, RAND_OUI, RAND_OUI, "x");
    b[0] = 0x08; // data frame, not mgmt
    CHECK(pwnpal_flock_match(b, len, &dev) == FLOCK_NONE, "non-mgmt -> none");
    // addr1 (receiver) multicast must not trigger an OUI hit even if it matches
    len = mk_beacon(b, RAND_OUI, RAND_OUI, "x");
    b[4] = FLOCK_OUI[0]; b[5] = FLOCK_OUI[1]; b[6] = FLOCK_OUI[2]; // addr1 = flock OUI but multicast bit...
    b[4] |= 0x01; // force multicast
    CHECK(pwnpal_flock_match(b, len, &dev) == FLOCK_NONE, "multicast addr1 OUI ignored");

    printf("%s (%d failures)\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
