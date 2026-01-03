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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

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

void app_main(void)
{
    pn5180_spi_t *spi = pn5180_spi_init(VSPI_HOST, PN5180_SCK, PN5180_MISO, PN5180_MOSI, PN5180_FREQ);
    if (spi == NULL) {
        printf("Failed to initialize PN5180 SPI\n");
        return;
    }
    pn5180_t *pn5180 = pn5180_init(spi, PN5180_NSS, PN5180_BUSY, PN5180_RST);
    if (pn5180 == NULL) {
        printf("Failed to initialize PN5180\n");
        return;
    }
    printf("PN5180 initialized successfully\n");

    printf("----------------------------------\n");
    printf("Reading product version...\n");
    uint8_t productVersion[2];
    if (pn5180_readEEprom(pn5180, PRODUCT_VERSION, productVersion, sizeof(productVersion))) {
        printf("Product version=");
        printf("%d", productVersion[1]);
        printf(".");
        printf("%d\n", productVersion[0]);
        if (0xff == productVersion[1]) { // if product version 255, the initialization failed
            printf("Initialization failed!?\n");
            printf("Press reset to restart...\n");
            fflush(stdout);
            exit(-1); // halt
        }
    } else {
        printf("Failed to read product version\n");
    }
    printf("----------------------------------\n");
    printf("Reading firmware version...\n");
    uint8_t firmwareVersion[2];
    if (pn5180_readEEprom(pn5180, FIRMWARE_VERSION, firmwareVersion, sizeof(firmwareVersion))) {
        printf("Firmware version=");
        printf("%d", firmwareVersion[1]);
        printf(".");
        printf("%d\n", firmwareVersion[0]);
    } else {
        printf("Failed to read firmware version\n");
    }
    printf("----------------------------------\n");
    printf("Reading EEPROM version...\n");
    uint8_t eepromVersion[2];
    if (pn5180_readEEprom(pn5180, EEPROM_VERSION, eepromVersion, sizeof(eepromVersion))) {
        printf("EEPROM version=");
        printf("%d", eepromVersion[1]);
        printf(".");
        printf("%d\n", eepromVersion[0]);
    } else {
        printf("Failed to read EEPROM version\n");
    }
    printf("----------------------------------\n");
    pn5180_proto_t *proto_14443 = pn5180_14443_init(pn5180);
    if (proto_14443 == NULL) {
        printf("Failed to initialize PN5180 ISO14443 protocol\n");
        pn5180_deinit(pn5180, true);
        return;
    }
    printf("PN5180 ISO14443 protocol initialized successfully\n");
    while (true) {
        printf("Scanning for ISO14443A cards...\n");
        { // Reset RF field
            pn5180_setRF_off(pn5180);
            pn5180_delay_ms(5);
            esp_rom_delay_us(100);
            proto_14443->setup_rf(proto_14443);
        }
        nfc_uids_array_t *uids = proto_14443->get_all_uids(proto_14443);
        if (uids == NULL) {
            printf("No cards found.\n");
        } else {
            printf("Found %d card(s):\n", uids->uids_count);
            for (int i = 0; i < uids->uids_count; i++) {
                printf(" Card %d: UID Length=%d, UID=", i + 1, uids->uids[i].uid_length);
                for (int j = 0; j < uids->uids[i].uid_length; j++) {
                    printf("%02X ", uids->uids[i].uid[j]);
                }
                printf("\n");
            }
            free(uids);
        }
        pn5180_delay_ms(2000);
    }
    pn5180_deinit(pn5180, true);
    printf("PN5180 deinitialized\n");
}
