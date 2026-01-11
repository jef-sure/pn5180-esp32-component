/*
 * SPDX-FileCopyrightText: 2010-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_chip_info.h"
#include "esp_err.h"
#include "esp_flash.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "pn5180-14443.h"
#include "pn5180.h"
#include "sdkconfig.h"
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static const char *TAG = "main";

enum
{
    PN5180_RST  = GPIO_NUM_12,
    PN5180_SCK  = GPIO_NUM_18,
    PN5180_MOSI = GPIO_NUM_23,
    PN5180_MISO = GPIO_NUM_19,
    PN5180_NSS  = GPIO_NUM_5,
    PN5180_BUSY = GPIO_NUM_21,
    PN5180_FREQ = 7000000,
};

// Candidate keys to try (user-provided defaults)
static const uint8_t mifare_keys[][6] = {
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
    {0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0},
    {0xA1, 0xB1, 0xC1, 0xD1, 0xE1, 0xF1},
    {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
    {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5},
    {0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD},
    {0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7},
    {0x71, 0x4C, 0x5C, 0x88, 0x6E, 0x97},
    {0x58, 0x7E, 0xE5, 0xF9, 0x35, 0x0F},
    {0xA0, 0x47, 0x8C, 0xC3, 0x90, 0x91},
    {0x53, 0x3C, 0xB6, 0xC7, 0x23, 0xF6},
    {0x8F, 0xD0, 0xA4, 0xF2, 0x56, 0xE9},
};
static const uint8_t key_types[] = {MIFARE_CLASSIC_KEYA, MIFARE_CLASSIC_KEYB};

static const char *get_card_type_name(mifare_type_t subtype)
{
    switch (subtype) {
    case PN5180_MIFARE_CLASSIC_1K:
        return "MIFARE Classic 1K";
    case PN5180_MIFARE_CLASSIC_MINI:
        return "MIFARE Classic Mini";
    case PN5180_MIFARE_CLASSIC_4K:
        return "MIFARE Classic 4K";
    case PN5180_MIFARE_ULTRALIGHT:
        return "MIFARE Ultralight";
    case PN5180_MIFARE_ULTRALIGHT_C:
        return "MIFARE Ultralight C";
    case PN5180_MIFARE_ULTRALIGHT_EV1:
        return "MIFARE Ultralight EV1";
    case PN5180_MIFARE_NTAG213:
        return "NTAG213";
    case PN5180_MIFARE_NTAG215:
        return "NTAG215";
    case PN5180_MIFARE_NTAG216:
        return "NTAG216";
    case PN5180_MIFARE_PLUS_2K:
        return "MIFARE Plus 2K";
    case PN5180_MIFARE_PLUS_4K:
        return "MIFARE Plus 4K";
    case PN5180_MIFARE_DESFIRE:
        return "MIFARE DESFire";
    default:
        return "Unknown";
    }
}

static bool requires_authentication(mifare_type_t subtype)
{
    return (subtype == PN5180_MIFARE_CLASSIC_1K || subtype == PN5180_MIFARE_CLASSIC_MINI ||
            subtype == PN5180_MIFARE_CLASSIC_4K || subtype == PN5180_MIFARE_PLUS_2K ||
            subtype == PN5180_MIFARE_PLUS_4K);
}

static int get_sector_from_block(mifare_type_t subtype, int block)
{
    if (subtype == PN5180_MIFARE_CLASSIC_4K && block >= 128) {
        // Sectors 32-39 have 16 blocks each
        return 32 + (block - 128) / 16;
    } else {
        // Sectors 0-31 have 4 blocks each
        return block / 4;
    }
}

static int get_sector_first_block(mifare_type_t subtype, int sector)
{
    if (subtype == PN5180_MIFARE_CLASSIC_4K && sector >= 32) {
        // Sectors 32-39 start at block 128, 144, 160, ...
        return 128 + (sector - 32) * 16;
    } else {
        // Sectors 0-31 start at blocks 0, 4, 8, ...
        return sector * 4;
    }
}

static bool authenticate_sector(pn5180_proto_t *proto, nfc_uid_t *uid, int sector_block)
{
    if (proto->authenticate == NULL) {
        return false;
    }

    for (size_t ki = 0; ki < ARRAY_SIZE(mifare_keys); ki++) {
        for (size_t kt = 0; kt < ARRAY_SIZE(key_types); kt++) {
            if (proto->authenticate(proto, mifare_keys[ki], key_types[kt], uid, sector_block)) {
                int sector = get_sector_from_block(uid->subtype, sector_block);
                ESP_LOGI(TAG, "Sector %2d authenticated with key %zu (%s)", sector, ki,
                         (key_types[kt] == MIFARE_CLASSIC_KEYA) ? "KeyA" : "KeyB");
                return true;
            }
        }
    }
    return false;
}

static void print_block_data(int block, const uint8_t *data, int size)
{
    printf("    Block %3d: ", block);
    for (int i = 0; i < size; i++) {
        printf("%02X ", data[i]);
    }
    printf(" | ");
    for (int i = 0; i < size; i++) {
        printf("%c", isprint(data[i]) ? data[i] : '.');
    }
    printf("\n");
}

static void read_card_blocks(pn5180_proto_t *proto, nfc_uid_t *uid, int blocks_count, int block_size)
{
    if (blocks_count <= 0 || block_size <= 0 || proto->block_read == NULL) {
        return;
    }

    printf("  Reading all blocks:\n");
    uint8_t  small_block_data[16];
    uint8_t *block_data = block_size < 16 ? small_block_data : malloc(block_size);
    if (block_data == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for block data");
        return;
    }

    bool needs_auth      = requires_authentication(uid->subtype);
    int  current_sector  = -1;
    bool stop_after_fail = false;

    for (int block = 0; block < blocks_count; block++) {
        if (stop_after_fail) {
            break;
        }

        // Authenticate at the start of each sector
        if (needs_auth) {
            int sector = get_sector_from_block(uid->subtype, block);

            if (sector != current_sector) {
                int sector_block = get_sector_first_block(uid->subtype, sector);

                if (!authenticate_sector(proto, uid, sector_block)) {
                    ESP_LOGW(TAG, "Block %3d: Authentication failed (keys unknown)", block);
                    stop_after_fail = true;
                    continue;
                }
                current_sector = sector;
            }
        }

        if (proto->block_read(proto, block, block_data)) {
            print_block_data(block, block_data, block_size);
        } else {
            ESP_LOGW(TAG, "Block %3d: Read failed", block);
            // Retry once for any transient read failure (all card types)
            if (proto->block_read(proto, block, block_data)) {
                ESP_LOGI(TAG, "Block %3d: Read succeeded on retry", block);
                print_block_data(block, block_data, block_size);
            } else {
                ESP_LOGW(TAG, "Block %3d: Read failed on retry - skipping block", block);
                // Lost authentication state if applicable - must re-authenticate for next block in sector
                if (needs_auth) {
                    current_sector = -1;
                }
            }
        }
    }
    if (block_data != small_block_data) free(block_data);
}

static void process_card(pn5180_proto_t *proto, nfc_uid_t *uid)
{
    // Print UID
    printf("UID Length=%d, UID=", uid->uid_length);
    for (int j = 0; j < uid->uid_length; j++) {
        printf("%02X ", uid->uid[j]);
    }
    printf("\n");

    // Select card
    if (!proto->select_by_uid(proto, uid)) {
        ESP_LOGE(TAG, "Failed to select card");
        return;
    }

    // Get card type details
    int  blocks_count   = 0;
    int  block_size     = 0;
    bool needs_reselect = proto->detect_card_type_and_capacity(proto->pn5180, uid, &blocks_count, &block_size);

    // Reselect card if required after card type detection
    if (needs_reselect) {
        if (!proto->select_by_uid(proto, uid)) {
            ESP_LOGE(TAG, "Failed to reselect card after type detection");
            return;
        }
    }

    printf("  Type: %s\n", get_card_type_name(uid->subtype));
    printf("  Blocks: %d, Block size: %d bytes\n", blocks_count, block_size);

    // Read all blocks
    read_card_blocks(proto, uid, blocks_count, block_size);
}

static bool read_version(pn5180_t *pn5180, uint8_t addr, const char *name)
{
    uint8_t version[2];
    if (!pn5180_readEEprom(pn5180, addr, version, sizeof(version))) {
        ESP_LOGE(TAG, "Failed to read %s", name);
        return false;
    }

    ESP_LOGI(TAG, "%s: %d.%d", name, version[1], version[0]);

    // Check for initialization failure
    if (addr == PRODUCT_VERSION && version[1] == 0xff) {
        ESP_LOGE(TAG, "Initialization failed - invalid product version");
        return false;
    }

    return true;
}

static bool init_pn5180_hardware(pn5180_t **pn5180_out)
{
    // Initialize SPI
    pn5180_spi_t *spi = pn5180_spi_init(VSPI_HOST, PN5180_SCK, PN5180_MISO, PN5180_MOSI, PN5180_FREQ);
    if (spi == NULL) {
        ESP_LOGE(TAG, "Failed to initialize PN5180 SPI");
        return false;
    }

    // Initialize PN5180
    pn5180_t *pn5180 = pn5180_init(spi, PN5180_NSS, PN5180_BUSY, PN5180_RST);
    if (pn5180 == NULL) {
        ESP_LOGE(TAG, "Failed to initialize PN5180");
        return false;
    }

    ESP_LOGI(TAG, "PN5180 initialized successfully");

    // Read versions
    if (!read_version(pn5180, PRODUCT_VERSION, "Product version") ||
        !read_version(pn5180, FIRMWARE_VERSION, "Firmware version") ||
        !read_version(pn5180, EEPROM_VERSION, "EEPROM version")) {
        pn5180_deinit(pn5180, true);
        return false;
    }

    *pn5180_out = pn5180;
    return true;
}

static void scan_loop(pn5180_proto_t *proto)
{
    while (true) {
        ESP_LOGD(TAG, "Free heap before scanning: %lu", esp_get_free_heap_size());
        ESP_LOGI(TAG, "Scanning for ISO14443A cards...");

        // Reset transceiver and RF field completely
        pn5180_set_transceiver_idle(proto->pn5180);
        pn5180_writeRegisterWithAndMask(proto->pn5180, SYSTEM_CONFIG, 0xFFFFFFBF); // Clear Crypto1
        pn5180_clearIRQStatus(proto->pn5180, 0xFFFFFFFF);
        pn5180_setRF_off(proto->pn5180);
        pn5180_delay_ms(10);
        proto->setup_rf(proto);

        // Get all UIDs
        nfc_uids_array_t *uids = proto->get_all_uids(proto);
        if (uids == NULL) {
            ESP_LOGI(TAG, "No cards found");
        } else {
            ESP_LOGI(TAG, "Found %d card(s)", uids->uids_count);
            for (int i = 0; i < uids->uids_count; i++) {
                printf("Card %d UID: ", i + 1);
                for (int j = 0; j < uids->uids[i].uid_length; j++) {
                    printf("%02X ", uids->uids[i].uid[j]);
                }
                printf("\n");
            }
            for (int i = 0; i < uids->uids_count; i++) {
                printf("Card %d: ", i + 1);
                process_card(proto, &uids->uids[i]);
                printf("\n");
            }
            free(uids);
        }

        pn5180_delay_ms(2000);
        ESP_LOGD(TAG, "Free heap after scanning: %lu", esp_get_free_heap_size());
        assert(heap_caps_check_integrity_all(true));
    }
}

void app_main(void)
{
    // Initialize hardware
    pn5180_t *pn5180 = NULL;
    if (!init_pn5180_hardware(&pn5180)) {
        ESP_LOGE(TAG, "Hardware initialization failed");
        return;
    }

    // Initialize ISO14443 protocol
    pn5180_proto_t *proto_14443 = pn5180_14443_init(pn5180);
    if (proto_14443 == NULL) {
        ESP_LOGE(TAG, "Failed to initialize ISO14443 protocol");
        pn5180_deinit(pn5180, true);
        return;
    }
    ESP_LOGI(TAG, "ISO14443 protocol initialized successfully");

    // Start scanning loop
    scan_loop(proto_14443);
}
