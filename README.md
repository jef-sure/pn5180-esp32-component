# PN5180 ESP32 Component (ESP-IDF)

## Overview

ESP-IDF component for the NXP PN5180 NFC/RFID reader. This implementation provides a robust ISO14443A reader with comprehensive MIFARE Classic and Ultralight support.

### Status
- ✅ Fully tested with ESP32 and PN5180 over VSPI at 7 MHz
- ✅ ISO14443A anticollision and multi-cascade UID enumeration
- ✅ MIFARE Classic 1K/4K authentication and block read/write with reliable error detection
- ✅ MIFARE Ultralight support (read-only, single cascade)
- ✅ Multi-sector authentication with automatic session management
- ✅ RX error detection and automatic retry for corrupted reads
- ✅ Comprehensive state polling and synchronization
- ✅ RF field control and card detection
- ✅ Version/EEPROM reads

## Hardware

Default wiring used in the sample app:

| Signal | ESP32 GPIO |
| ------ | ---------- |
| RST    | 12         |
| SCK    | 18         |
| MOSI   | 23         |
| MISO   | 19         |
| NSS    | 5          |
| BUSY   | 21         |

Adjust the GPIO assignments or the SPI host (`VSPI_HOST` by default) to match your board.

## Requirements

- ESP-IDF v5.x (tested) with an ESP32 target.
- 3.3 V PN5180 breakout wired for SPI and BUSY/RST lines.
- Enough DMA-capable heap for the driver buffers (two 512-byte buffers are allocated).

## Getting Started

1) Place this repository under your project's `components/` directory (or add it as a git submodule).
2) Include the headers you need: `pn5180.h` for the core driver and `pn5180-14443.h` for ISO14443A helpers.
3) Build and flash with `idf.py build flash monitor`.

**Note**: The `main/` directory contains an example application demonstrating card enumeration and block reading. Replace it with your own application logic.

## Usage Example

```c
#include "pn5180.h"
#include "pn5180-14443.h"

enum {
    PN5180_RST  = GPIO_NUM_12,
    PN5180_SCK  = GPIO_NUM_18,
    PN5180_MOSI = GPIO_NUM_23,
    PN5180_MISO = GPIO_NUM_19,
    PN5180_NSS  = GPIO_NUM_5,
    PN5180_BUSY = GPIO_NUM_21,
    PN5180_FREQ = 7000000,
};

void app_main(void)
{
    pn5180_spi_t *spi = pn5180_spi_init(VSPI_HOST, PN5180_SCK, PN5180_MISO, PN5180_MOSI, PN5180_FREQ);
    pn5180_t *pn5180  = pn5180_init(spi, PN5180_NSS, PN5180_BUSY, PN5180_RST);

    pn5180_proto_t *iso14443 = pn5180_14443_init(pn5180);
    iso14443->setup_rf(iso14443);

    nfc_uids_array_t *uids = iso14443->get_all_uids(iso14443);
    if (uids) {
        for (int i = 0; i < uids->uids_count; i++) {
            // process uids->uids[i]
        }
        free(uids);
    }

    free(iso14443);
    pn5180_deinit(pn5180, true);
}
```

## Notes

- **Blocking calls & timeouts**: All APIs are synchronous and wait for hardware completion using `BUSY`, IRQ, and transceiver-state polling. No hidden delays; operations respect internal timeouts and return promptly on error.
- **Error handling boundaries**: The component detects RX errors (protocol/CRC/collision) and returns failure without attempting automatic retries. Implement retries in your application according to your policy.
- **Authentication behavior**: On auth failure, the driver resets to a clean idle state; you may retry with the same or different key. The driver does not perform HALT/reselect between sectors.
- **CRC policy (ISO14443A)**: Anticollision runs with CRC disabled; SELECT uses CRC enabled. After the final SELECT, CRC remains enabled (e.g., ready for MIFARE Classic AUTH).
- **Crypto1 session**: The driver does not toggle hardware Crypto1 bits. Session integrity is preserved by failing fast on RX errors; application-level retries avoid corruption.
- **RF field control**: Toggle RF off/on between scans and allow ~5.1 ms for tags to return to IDLE.
- **UID enumeration**: `iso14443->get_all_uids(iso14443)` returns a heap-allocated array (max 14 cards). Free after use; returns NULL if none detected.
- **Runtime configuration**: Pins and SPI frequency are set in your app; there are no Kconfig options in this component.

## License

MIT License