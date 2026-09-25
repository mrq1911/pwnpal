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
