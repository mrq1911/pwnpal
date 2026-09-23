#pragma once

#include <furi_hal.h>

// serial link to the ESP32 board; same USART/baud as Marauder's CLI, no rewiring
#define PWNPAL_UART_CHANNEL FuriHalSerialIdUsart
#define PWNPAL_UART_BAUD 115200

// secs between persona re-pushes to the ESP32 so its beacon reflects growing counts
#define PWNPAL_ADV_RESEND_SECS 15

// secs between persona saves to SD
#define PWNPAL_SAVE_SECS 30

// ESP32-absence: board sends PWNPAL_ADV ~2x/sec; silence for LINK_TIMEOUT after
// LINK_GRACE (covers boot + StartScan) warns the user
#define PWNPAL_LINK_TIMEOUT_SECS 5
#define PWNPAL_LINK_GRACE_SECS 10

// setup link QR'd on the "no ESP32" screen; <=53 bytes so the QR stays version-3 (29x29) at 2px/module
#define PWNPAL_SETUP_URL "https://github.com/mrq1911/pwnagotchi-flipper"

// serial-proto version this app expects (mirrors firmware PWNPAL_PROTO). firmware stamps
// ver=N on each PWNPAL_ADV; non-zero but below this -> board too old, warn the user
#define PWNPAL_FW_PROTO 6

// FLIPPER_SCREEN_WIDTH / _HEIGHT come from pwn_constants.h (via pwnagotchi.h).
