# Flock / ALPR detection (passive)

pwnpal can passively spot **Flock Safety** and other ALPR surveillance cameras while it wardrives
— on the *same pass* it captures handshakes and maps APs. Listen-only: it never transmits for
this, and it works with capture/deauth still off (no consent gate). Detections are **indicators,
not proof** — an OUI-only hit needs eyeballing.

Toggle: **Menu → Flock detect** (on by default; persisted in `home.bin` v7). The setting rides to
the ESP as `-flock 0|1`; off = the firmware skips the check entirely (no `PWNPAL_FLOCK`, no cost).

## How it works (Wi-Fi)

The ESP already sniffs every management frame in promiscuous mode across channels (the pwnpal
recon sweep); `reportFlock()` matches each one against `pwnpal_flock_match()` in
`pwnpal_frames.h` (pure, host-tested — `tests/test_flock.cpp`). Signatures, highest confidence
first (ported from CrowPanel-Flock-You / FlipDeFlock):

- **Probe-request IE fingerprint** — a wildcard-SSID probe whose Information Elements appear in the
  exact order `0,2,12,127,221(LiteOn),45,191,221(WPA)` with the two vendor payloads. This is the
  tell that **survives MAC randomization** (the address is useless, the radio's fingerprint isn't).
  *high*
- **Wildcard probe from a known Flock OUI** — *high*
- **SSID keyword** `flock` / `flck` (case-insensitive substring) — *medium*
- **Known Flock OUI** as transmitter (addr2) — *medium*; as receiver (addr1, non-multicast) or
  BSSID (addr3), or a hidden-SSID beacon from a Flock OUI — *low*

The OUI table (`PWNPAL_FLOCK_OUIS`, ~31 prefixes) lives in `pwnpal_frames.h`; update it as the
community list grows.

## Output

- `PWNPAL_FLOCK {"mac","method","conf","rssi","channel","ssid"[,"lat","lon"]}` on the wire, once
  per device per session (deduped on the ESP).
- Flipper side: a session **count** (shown on the Flock-detect menu row), a blink/vibro (unless
  Quiet), a brief **"flock spotted!"** persona shout, and a row appended to
  `/ext/apps_data/pwnpal/flock.csv` (`uptime,mac,method,conf,rssi,channel,lat,lon,ssid`) —
  DeFlock/WiGLE-friendly. `PWNPAL_EPOCH` also carries a per-epoch `flock` count.
- **On-device list**: once at least one device is spotted, **OK on the Flock-detect menu row**
  opens a scrollable list (mac/ssid + `H`/`M`/`L` confidence + signal); OK on a row shows a detail
  (mac, method+confidence, channel, rssi, age, coords), and OK there shows a `geo:` **map QR** for
  geotagged hits. The device table is session-only and uses
  the **same overflow rule as the AP table** — capped at `FLOCK_MAX` (64), recycling the
  least-recently-seen slot; the count shows `+` once devices have been recycled.

## Why native (vs a separate app)

FlipDeFlock is the mature standalone (Wi-Fi + BLE, great tool), but its firmware is **either/or**:
its Marauder-scrape mode is feature-limited, and its full detection needs a **companion firmware
that replaces Marauder**. pwnpal's whole point is one flash = Marauder + pwnagotchi coexisting, so
folding Flock detection in means **camera-spotting + capture + wardrive geotag in a single image**,
no reflash, no mode-switch.

## Possible improvements

- **BLE detection** — Flock beacons expose BLE tells (`Penguin-NNNNNNNNNN` names, `FS Ext Battery`
  manufacturer data, XUNTONG mfg id `0x09C8`, 10-digit names + OUI). ESP32 can't run Wi-Fi
  promiscuous and BLE scan at once, so this needs recon/BLE radio time-slicing (the same reason
  FlipDeFlock gates BLE behind its companion FW). Phase 2.
- **Marauder-compatible mode** — a Flipper-side scrape path that detects Flock from **stock ESP32
  Marauder** output (à la FlipDeFlock's Marauder mode), so users who haven't flashed the pwnpal
  firmware still get basic detection. Note the tradeoff vs the native mode here: the full-signature
  detection above **requires flashing the pwnpal firmware**; the scrape mode would be flash-free
  but limited to what Marauder prints (OUI/SSID, no IE fingerprint).
- **Signature upkeep** — periodic refresh of `PWNPAL_FLOCK_OUIS` and the IE fingerprint from the
  DeFlock / Flock-You datasets.
- **Confidence surfacing** — show method/confidence per hit in the UI so low-confidence OUI-only
  matches are clearly flagged for eyeball confirmation.

## Ethics / legality

Passive, listen-only, cameras-only. No deauth, injection, or jamming is involved in detection.
Detections are indicators to verify by eye, for anti-surveillance awareness and authorized
security assessment / research only. Comply with local law.
