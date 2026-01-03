# PN5180 ESP32 Component (ESP-IDF)

## Overview

ESP-IDF component for the NXP PN5180 NFC/RFID reader. The current implementation focuses on ISO14443A polling with basic MIFARE Classic helpers (UID discovery, select, authenticate, block read/write) using the ESP32 SPI peripheral.

### Status
- Tested with ESP32 and PN5180 over VSPI at 7 MHz (see default pins below).
- ISO14443A anticollision and UID enumeration are implemented.
- MIFARE Classic authentication and block read/write helpers are available.
- Version/EEPROM reads and RF on/off helpers are exposed.
- ISO15693 and other tag types are not implemented yet (stub header only).

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

- Operations are blocking; there is no background task or IRQ handler required beyond the PN5180 `BUSY` line.
- `iso14443->get_all_uids(iso14443)` returns a heap-allocated UID array (flexible array, up to 14 entries); free the returned pointer once (returns NULL when no cards).
- Before each UID scan, toggle the RF field off and wait at least ~5.1 ms so tags return to IDLE; the sample does this prior to calling `get_all_uids`.
- If you change the SPI frequency or pins, ensure they match your board’s wiring and PN5180 timing limits.
- There are no Kconfig options; configure pins in your application code.
- The example frees the protocol wrapper before deinitializing the driver; do the same if you allocate it once per app.

## License

MIT License