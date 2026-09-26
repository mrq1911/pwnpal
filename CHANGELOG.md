# Changelog

Versions continue this repo's tag lineage (the original flipagotchi released up to
`v2.1.1`); `v3.0.0` is the first **pwnpal** release.

## Unreleased

### Added
- **Passive Flock / ALPR detection** — spots Flock Safety and other ALPR cameras by their Wi-Fi
  signatures (known OUIs, `flock`/`flck` SSIDs, and a wildcard-probe IE fingerprint that beats MAC
  randomization) on the same wardrive pass. Togglable (Menu → Flock detect, on by default),
  listen-only. Hits blink + shout, log to `flock.csv` (DeFlock/WiGLE-friendly), and are browsable
  on-device (list → detail → map QR). See [doc/FlockDetection.md](doc/FlockDetection.md).

## v3.0.0 — pwnpal

First release under the pwnpal name: the Flipper + an ESP32 Marauder-fork board become a
full, self-contained pwnagotchi.

### Added
- **Social pwngrid peer** — broadcasts a pwnagotchi-compatible beacon, sniffs and remembers
  other units, and grows a persona that levels up with encounters.
- **Real capture** — WPA/WPA2 4-way handshakes and PMKID, saved as per-BSSID `.pcap` for
  hashcat `-m 22000`. A capture is only marked crackable once a genuine EAPOL pair
  (ANonce + M2) or a self-contained PMKID is in hand.
- **De-cloak** — recovers hidden ESSIDs from clients' (re)association requests and splices
  them into the capture, turning otherwise-uncrackable loot crackable. De-cloaked APs are
  marked in the list and logged to `decloak.csv`.
- **GPS wardrive** — geotags APs, writes a WiGLE-compatible `wardrive.csv`, and shows live
  distance/bearing to a saved home.
- **Capture modes** — Wardrive, Roam, Siege, and Auto (switches by movement).
- **On-device browser** — recent APs and pwned APs with live signal bars, per-AP client
  counts, target/ignore/de-cloak markers, a pwned skull, and a per-AP detail + map QR.
- **Battery saver** — light/deep duty-cycling with auto-off on external power.
- **Firmware-match nudge** — the app recommends a reflash when the board's firmware build
  lags the app.
- **Web export** — an offline page converts captures to hashcat 22000 and maps the wardrive.

### Fixed
- Auto mode now feeds live GPS fixes into the movement detector, so it no longer stays stuck
  in siege while driving.
- Already-captured APs are no longer re-counted as new pwns after a restart.
- The AP list holds a stable order while you scroll instead of reshuffling on every RSSI tick.

### Notes
- **Authorized use only.** Association, deauthentication and handshake capture are active
  radio attacks; they ship off behind a one-time on-device consent gate.
- Requires an ESP32 running the bundled Marauder fork (single flash = full Marauder + the
  `pwnpal` command). See `README.md` and `COMPATIBLE_HARDWARE.md`.
