// pure 802.11 parsers for pwnpal — hardware-free (only stdint/stddef) so host-testable
// (see tests/). anything touching esp_wifi/Serial belongs in Pwnpal.cpp.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// does this beacon/probe-response require 802.11w PMF (RSN MFPR bit)? if so deauth is
// futile, PMKID only. walks tagged params to the RSN IE (id 48) caps. bounds-checked,
// false on malformed input.
static inline bool pwnpal_rsn_requires_pmf(const uint8_t* f, int len) {
    int p = 36; // tagged params start after the 24-byte mgmt hdr + 12-byte fixed params
    while(p + 2 <= len) {
        int id = f[p], l = f[p + 1];
        if(p + 2 + l > len) break;
        if(id == 48 && l >= 2) { // RSN IE
            const uint8_t* r = f + p + 2;
            int off = 2; // version
            if(off + 4 > l) return false;
            off += 4; // group cipher suite
            if(off + 2 > l) return false;
            int pc = r[off] | (r[off + 1] << 8); // pairwise cipher count
            off += 2 + 4 * pc;
            if(off + 2 > l) return false;
            int ac = r[off] | (r[off + 1] << 8); // AKM suite count
            off += 2 + 4 * ac;
            if(off + 1 > l) return false;
            return (r[off] & 0x40) != 0; // RSN capabilities bit 6 = MFPR (required)
        }
        p += 2 + l;
    }
    return false;
}

// --- EAPOL / 4-way parsing (extracted from reportHandshake; pure + host-tested) ---

// Locate the 802.1X (EAPOL) header: scan for the 0x888e etherType in the LLC/SNAP region and
// return the offset of the 802.1X version byte just past it, or -1 if not present. Bounded to
// the LLC/etherType window (bytes 30..40) so a coincidental 88 8e deeper in the payload — or in
// the MAC header — can't false-match. Handles both the no-QoS (etherType@30) and QoS (@32) layouts.
static inline int pwnpal_eapol_locate(const uint8_t* f, int len) {
    int end = len - 2;
    if(end > 40) end = 40;
    for(int i = 30; i <= end; i++)
        if(f[i] == 0x88 && f[i + 1] == 0x8e) return i + 2;
    return -1;
}

typedef struct {
    bool key_ack, key_mic, secure, install; // key_info bits 7, 8, 9, 6
    uint8_t nonce[32];
    bool nonce_nz; // Key Nonce: ANonce on M1/M3, SNonce on M2, ~zero on M4
    uint8_t replay[8]; // EAPOL-Key replay counter (pairs M1<->M2)
    uint8_t pmkid[16];
    bool pmkid_nz; // RSN PMKID KDE present + non-zero (M1 PMKID attack)
} PwnpalEapolKey;

// Parse the EAPOL-Key frame whose 802.1X header starts at `eo` (from pwnpal_eapol_locate).
// Returns false if it isn't an EAPOL-Key or is truncated before key_info; on true *out is filled.
// Field offsets (from eo): key_info@5, key_len@7, replay@9(8), nonce@17(32), MIC@81(16),
// key-data-len@97(2), key-data@99 — byte-for-byte the gopacket/bettercap layout. Bounds-checked.
static inline bool pwnpal_eapol_key(const uint8_t* f, int len, int eo, PwnpalEapolKey* out) {
    if(eo < 0 || eo + 6 >= len) return false; // need at least through key_info
    if(f[eo + 1] != 0x03) return false; // 802.1X type must be Key (0x03)
    for(int i = 0; i < 32; i++) out->nonce[i] = 0;
    for(int i = 0; i < 8; i++) out->replay[i] = 0;
    for(int i = 0; i < 16; i++) out->pmkid[i] = 0;
    uint16_t ki = (uint16_t)((f[eo + 5] << 8) | f[eo + 6]);
    out->key_ack = (ki & (1 << 7)) != 0;
    out->key_mic = (ki & (1 << 8)) != 0;
    out->secure = (ki & (1 << 9)) != 0;
    out->install = (ki & (1 << 6)) != 0;
    for(int b = 0; b < 8 && eo + 9 + b < len; b++) out->replay[b] = f[eo + 9 + b];
    out->nonce_nz = false;
    for(int b = 0; b < 32 && eo + 17 + b < len; b++) {
        out->nonce[b] = f[eo + 17 + b];
        if(out->nonce[b]) out->nonce_nz = true;
    }
    // RSN PMKID KDE in Key Data: DD <len> 00 0F AC 04 <16-byte PMKID>. WPA1 vendor KDEs use OUI
    // 00 50 F2, so the 00 0F AC 04 match can't false-positive on them.
    out->pmkid_nz = false;
    int kdl_off = eo + 97;
    if(kdl_off + 1 < len) {
        int kdl = (f[kdl_off] << 8) | f[kdl_off + 1];
        int kd = kdl_off + 2;
        int kd_end = kd + kdl;
        if(kd_end > len) kd_end = len;
        for(int i = kd; i + 22 <= kd_end; i++) {
            if(f[i] == 0xDD && f[i + 2] == 0x00 && f[i + 3] == 0x0F && f[i + 4] == 0xAC &&
               f[i + 5] == 0x04) {
                for(int b = 0; b < 16; b++) {
                    out->pmkid[b] = f[i + 6 + b];
                    if(out->pmkid[b]) out->pmkid_nz = true;
                }
                break;
            }
        }
    }
    return true;
}

// BSSID from the To-DS/From-DS bits (FC byte 1); optionally also returns the client (non-AP)
// address. Mirrors the derivation in reportHandshake/reportClient. Callers pass frames already
// known to be >= EAPOL-length (pwnpal_eapol_locate succeeded), so addr3@16 is in bounds.
static inline const uint8_t* pwnpal_ds_bssid(const uint8_t* f, int len, const uint8_t** client) {
    (void)len;
    const uint8_t* bssid;
    const uint8_t* cli;
    bool tods = (f[1] & 0x01) != 0;
    bool fromds = (f[1] & 0x02) != 0;
    if(fromds && !tods) {
        bssid = f + 10; cli = f + 4; // AP->STA: Addr2=BSSID, Addr1=STA
    } else if(!fromds && tods) {
        bssid = f + 4; cli = f + 10; // STA->AP: Addr1=BSSID, Addr2=STA
    } else if(!fromds && !tods) {
        bssid = f + 16; cli = f + 10; // IBSS: Addr3=BSSID
    } else {
        bssid = f + 10; cli = f + 4; // WDS: fallback
    }
    if(client) *client = cli;
    return bssid;
}

// --- per-client 4-way pairing (Phase B) -----------------------------------------------------
// A captured "handshake" only cracks if M1 (ANonce) and M2 (SNonce+MIC) are from the SAME AP and
// client and carry the SAME replay counter, close in time. Tracking a single anonce/m2 per AP is
// wrong (M1 from client A + M2 from client B would falsely count). This is a global half table.
typedef struct {
    uint8_t ap_idx; // index into the recon table (AP)
    uint8_t client[6]; // the non-AP station
    uint8_t replay[8]; // EAPOL-Key replay counter (M1 and its M2 share it)
    uint32_t ms; // millis() when this half was seen (for the pairing window + eviction)
    bool is_m1; // true = ANonce half (M1), false = SNonce+MIC half (M2)
    bool used; // slot occupied
} PwnpalHsHalf;

// Record one handshake half and check whether it completes a 4-way with a half already stored.
// Returns true iff a matching OPPOSITE half (same ap/client/replay, within `window` ms) exists —
// on which it clears every stored half for that (ap, client). Otherwise the half is upserted
// (refresh same ap/client/kind, else take a free slot, else evict the oldest). Pure + testable.
static inline bool pwnpal_hs_insert_match(
    PwnpalHsHalf* t, int n, uint8_t ap_idx, const uint8_t* client, const uint8_t* replay,
    bool is_m1, uint32_t now, uint32_t window) {
    // 1. completing opposite half already present?
    for(int i = 0; i < n; i++) {
        if(!t[i].used || t[i].ap_idx != ap_idx || t[i].is_m1 == is_m1) continue;
        if(memcmp(t[i].client, client, 6) != 0 || memcmp(t[i].replay, replay, 8) != 0) continue;
        if((uint32_t)(now - t[i].ms) > window) continue; // stale -> not a pair
        for(int j = 0; j < n; j++) // complete: drop all halves for this (ap, client)
            if(t[j].used && t[j].ap_idx == ap_idx && memcmp(t[j].client, client, 6) == 0)
                t[j].used = false;
        return true;
    }
    // 2. no match: refresh an existing same-kind half, else a free slot, else evict oldest.
    int slot = -1;
    for(int i = 0; i < n; i++)
        if(t[i].used && t[i].ap_idx == ap_idx && t[i].is_m1 == is_m1 &&
           memcmp(t[i].client, client, 6) == 0) {
            slot = i;
            break;
        }
    if(slot < 0)
        for(int i = 0; i < n; i++)
            if(!t[i].used) {
                slot = i;
                break;
            }
    if(slot < 0) {
        slot = 0;
        for(int i = 1; i < n; i++)
            if((uint32_t)(now - t[i].ms) > (uint32_t)(now - t[slot].ms)) slot = i;
    }
    t[slot].used = true;
    t[slot].ap_idx = ap_idx;
    memcpy(t[slot].client, client, 6);
    memcpy(t[slot].replay, replay, 8);
    t[slot].is_m1 = is_m1;
    t[slot].ms = now;
    return false;
}

// --- Flock Safety / ALPR camera detection (passive) -----------------------------------------
// Signatures ported from CrowPanel-Flock-You / FlipDeFlock: known infra OUIs, SSID keywords, and
// the wildcard-probe Information-Element fingerprint that survives MAC randomization. All passive
// (listen-only). Detections are INDICATORS, not proof — an OUI-only hit needs eyeball confirming.

// Flock infrastructure OUI prefixes (NitekryDPaul + DeFlock/flock-you community lists). Update as
// it grows. NOTE: 00:03:7f (Qualcomm Atheros QCA9377) appears in some forks' lists — deliberately
// omitted here: it's a generic radio-vendor OUI on countless devices, so it floods false positives.
// Newer cameras also use locally-administered (non-IEEE) MACs to dodge OUI lists entirely — the
// probe IE fingerprint and SSID keyword paths below are what catch those.
static const uint8_t PWNPAL_FLOCK_OUIS[][3] = {
    {0x70, 0xc9, 0x4e}, {0x3c, 0x91, 0x80}, {0xd8, 0xf3, 0xbc}, {0x80, 0x30, 0x49},
    {0xb8, 0x35, 0x32}, {0x14, 0x5a, 0xfc}, {0x74, 0x4c, 0xa1}, {0x08, 0x3a, 0x88},
    {0x9c, 0x2f, 0x9d}, {0xc0, 0x35, 0x32}, {0x94, 0x08, 0x53}, {0xe4, 0xaa, 0xea},
    {0xf4, 0x6a, 0xdd}, {0xf8, 0xa2, 0xd6}, {0x24, 0xb2, 0xb9}, {0x00, 0xf4, 0x8d},
    {0xd0, 0x39, 0x57}, {0xe8, 0xd0, 0xfc}, {0xe0, 0x4f, 0x43}, {0xb8, 0x1e, 0xa4},
    {0x70, 0x08, 0x94}, {0x58, 0x8e, 0x81}, {0xec, 0x1b, 0xbd}, {0x3c, 0x71, 0xbf},
    {0x58, 0x00, 0xe3}, {0x90, 0x35, 0xea}, {0x5c, 0x93, 0xa2}, {0x64, 0x6e, 0x69},
    {0x48, 0x27, 0xea}, {0xa4, 0xcf, 0x12}, {0x82, 0x6b, 0xf2}, {0xb4, 0x1e, 0x52}, // Flock's own MA-L
};
#define PWNPAL_FLOCK_NOUI ((int)(sizeof(PWNPAL_FLOCK_OUIS) / 3))

// detection method, high confidence first (the app reports the name)
typedef enum {
    FLOCK_NONE = 0,
    FLOCK_PROBE_IE,   // wildcard probe + IE fingerprint (beats MAC randomization) - high
    FLOCK_PROBE_OUI,  // wildcard probe from a known OUI - high
    FLOCK_SSID,       // SSID contains flock/flck - medium
    FLOCK_OUI_ADDR2,  // known OUI as transmitter - medium
    FLOCK_OUI_ADDR1,  // known OUI as receiver - low
    FLOCK_HIDDEN_OUI, // hidden-SSID beacon/probe-resp from a known OUI - low
    FLOCK_OUI_ADDR3,  // known OUI as BSSID - low
} FlockMethod;

static inline bool pwnpal_oui_is_flock(const uint8_t* mac) {
    for(int i = 0; i < PWNPAL_FLOCK_NOUI; i++)
        if(mac[0] == PWNPAL_FLOCK_OUIS[i][0] && mac[1] == PWNPAL_FLOCK_OUIS[i][1] &&
           mac[2] == PWNPAL_FLOCK_OUIS[i][2])
            return true;
    return false;
}

// case-insensitive: does `hay` contain any of flock / flck?
static inline bool pwnpal_ssid_is_flock(const char* hay) {
    static const char* kw[] = {"flock", "flck"};
    for(int w = 0; w < 2; w++) {
        const char* k = kw[w];
        for(const char* h = hay; *h; h++) {
            int i = 0;
            while(k[i]) {
                char a = h[i], b = k[i];
                if(a >= 'A' && a <= 'Z') a += 32;
                if(a != b) break;
                i++;
            }
            if(!k[i]) return true;
        }
    }
    return false;
}

// find tagged IE `tag` walking TLVs from `start`; returns value ptr (sets *vlen) or NULL.
static inline const uint8_t* pwnpal_ie(const uint8_t* f, int len, int start, uint8_t tag, int* vlen) {
    int p = start;
    while(p + 2 <= len) {
        int id = f[p], l = f[p + 1];
        if(p + 2 + l > len) break;
        if(id == tag) {
            if(vlen) *vlen = l;
            return f + p + 2;
        }
        p += 2 + l;
    }
    return NULL;
}

// The Flock wildcard-probe IE fingerprint: an exact ordered TLV sequence with two vendor tags.
static inline bool pwnpal_flock_probe_ie_sig(const uint8_t* f, int len) {
    static const uint8_t LITEON[] = {0x50, 0x6f, 0x9a, 0x16, 0x03, 0x01, 0x03};
    static const uint8_t WPA[] = {0x00, 0x50, 0xf2, 0x08, 0x00, 0x00, 0x00};
    // expected: tag, is_vendor, vendor payload (first 7 bytes)
    struct {
        uint8_t tag;
        const uint8_t* vp;
    } exp[] = {
        {0, NULL}, {2, NULL}, {12, NULL}, {127, NULL}, {221, LITEON},
        {45, NULL}, {191, NULL}, {221, WPA},
    };
    int p = 24; // probe-request IEs start right after the 24-byte mgmt header (no fixed params)
    for(int e = 0; e < 8; e++) {
        if(p + 2 > len) return false;
        int id = f[p], l = f[p + 1];
        if(p + 2 + l > len) return false;
        if(id != exp[e].tag) return false;
        if(e == 0 && l != 0) return false; // tag 0 must be the wildcard (zero-length) SSID
        if(exp[e].vp) {
            if(l < 7) return false;
            for(int b = 0; b < 7; b++)
                if(f[p + 2 + b] != exp[e].vp[b]) return false;
        }
        p += 2 + l;
    }
    return true;
}

// Classify a management frame. Returns the highest-confidence method (FLOCK_NONE if not Flock)
// and, via *bssid_out, the address that identifies the device for logging.
static inline FlockMethod pwnpal_flock_match(const uint8_t* f, int len, const uint8_t** bssid_out) {
    if(len < 24) return FLOCK_NONE;
    if(((f[0] >> 2) & 0x3) != 0) return FLOCK_NONE; // management frames only
    uint8_t subtype = (f[0] >> 4) & 0xf;
    const uint8_t* addr1 = f + 4;  // receiver
    const uint8_t* addr2 = f + 10; // transmitter
    const uint8_t* addr3 = f + 16; // BSSID
    if(bssid_out) *bssid_out = addr2;
    bool oui2 = pwnpal_oui_is_flock(addr2);
    bool oui1 = !(addr1[0] & 0x01) && pwnpal_oui_is_flock(addr1); // skip multicast/broadcast RX
    bool oui3 = pwnpal_oui_is_flock(addr3);

    if(subtype == 4) { // probe request (no fixed params -> IEs at 24)
        int slen = -1;
        const uint8_t* ssid = pwnpal_ie(f, len, 24, 0, &slen);
        bool wildcard = (ssid != NULL) && slen == 0;
        // IE fingerprint is the strongest tell and works even with a randomized MAC.
        if(wildcard && pwnpal_flock_probe_ie_sig(f, len)) return FLOCK_PROBE_IE;
        if(oui2) return wildcard ? FLOCK_PROBE_OUI : FLOCK_OUI_ADDR2;
        if(oui1) {
            if(bssid_out) *bssid_out = addr1;
            return FLOCK_OUI_ADDR1;
        }
        return FLOCK_NONE;
    }

    if(subtype == 8 || subtype == 5) { // beacon / probe response (IEs at 36)
        int slen = -1;
        const uint8_t* ssid = pwnpal_ie(f, len, 36, 0, &slen);
        if(ssid && slen > 0) {
            char tmp[33];
            int n = slen > 32 ? 32 : slen;
            for(int i = 0; i < n; i++) tmp[i] = (char)ssid[i];
            tmp[n] = '\0';
            if(pwnpal_ssid_is_flock(tmp)) return FLOCK_SSID;
        }
        bool hidden = (ssid == NULL) || slen == 0 || ssid[0] == 0;
        if(oui2) return FLOCK_OUI_ADDR2;
        if(oui3) {
            if(bssid_out) *bssid_out = addr3;
            return hidden ? FLOCK_HIDDEN_OUI : FLOCK_OUI_ADDR3;
        }
        if(oui1) {
            if(bssid_out) *bssid_out = addr1;
            return FLOCK_OUI_ADDR1;
        }
    }
    return FLOCK_NONE;
}

// short label for a method (for the PWNPAL_FLOCK line + logs)
static inline const char* pwnpal_flock_method_name(FlockMethod m) {
    switch(m) {
    case FLOCK_PROBE_IE: return "probe-ie";
    case FLOCK_PROBE_OUI: return "probe-oui";
    case FLOCK_SSID: return "ssid";
    case FLOCK_OUI_ADDR2: return "oui-tx";
    case FLOCK_OUI_ADDR1: return "oui-rx";
    case FLOCK_HIDDEN_OUI: return "hidden-oui";
    case FLOCK_OUI_ADDR3: return "oui-bssid";
    default: return "none";
    }
}

static inline const char* pwnpal_flock_confidence(FlockMethod m) {
    switch(m) {
    case FLOCK_PROBE_IE:
    case FLOCK_PROBE_OUI: return "high";
    case FLOCK_SSID:
    case FLOCK_OUI_ADDR2: return "medium";
    default: return "low";
    }
}
