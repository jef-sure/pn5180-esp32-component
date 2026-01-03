#include "pn5180-14443.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <string.h>


static const char *TAG = "pn5180-14443";

static nfc_uids_array_t *pn5180_14443_get_all_uids(pn5180_t *pn5180);
static bool pn5180_14443_select_by_uid(pn5180_t *pn5180, nfc_uid_t *uid);
static bool pn5180_14443_mifareBlockRead(pn5180_t *pn5180, uint8_t blockno, uint8_t *buffer);
static int  pn5180_14443_mifareBlockWrite(pn5180_t *pn5180, uint8_t blockno, const uint8_t *buffer);
static bool pn5180_14443_mifareHalt(pn5180_t *pn5180);
static bool pn5180_14443_setupRF(pn5180_t *pn5180);

static bool _pn5180_14443_setupRF(pn5180_proto_t *proto) {
    return pn5180_14443_setupRF(proto->pn5180);
}

 static nfc_uids_array_t *_pn5180_14443_get_all_uids(pn5180_proto_t *proto) {
    return pn5180_14443_get_all_uids(proto->pn5180);
}

static bool _pn5180_14443_select_by_uid(pn5180_proto_t *proto, nfc_uid_t *uid) {
    return pn5180_14443_select_by_uid(proto->pn5180, uid);
}

static bool _pn5180_14443_mifareBlockRead(pn5180_proto_t *proto, uint8_t blockno, uint8_t *buffer) {
    return pn5180_14443_mifareBlockRead(proto->pn5180, blockno, buffer);
}

static int _pn5180_14443_mifareBlockWrite(pn5180_proto_t *proto, uint8_t blockno, const uint8_t *buffer) {
    return pn5180_14443_mifareBlockWrite(proto->pn5180, blockno, buffer);
}

pn5180_proto_t *pn5180_14443_init(pn5180_t *pn5180)
{
    pn5180_proto_t *proto = (pn5180_proto_t *)calloc(1, sizeof(pn5180_proto_t));
    if (proto == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for PN5180 14443 protocol");
        return NULL;
    }
    proto->pn5180        = pn5180;
    proto->setup_rf      = _pn5180_14443_setupRF;
    proto->get_all_uids  = _pn5180_14443_get_all_uids;
    proto->select_by_uid = _pn5180_14443_select_by_uid;
    proto->block_read    = _pn5180_14443_mifareBlockRead;
    proto->block_write   = _pn5180_14443_mifareBlockWrite;
    return proto;
}

static bool pn5180_14443_setupRF(pn5180_t *pn5180)
{
    if (pn5180->is_rf_on) {
        if (pn5180->tx_config == 0x00 && pn5180->rx_config == 0x80) {
            return true; // already configured
        }
        pn5180_setRF_off(pn5180);
    }
    // ISO14443 parameters
    bool ret = pn5180_loadRFConfig(pn5180, 0x00, 0x80); // 0x00: ISO14443-A 106kbit/s TX, 0x80: ISO14443-A 106kbit/s RX
    if (!ret) {
        ESP_LOGE(TAG, "Failed to load RF config for 14443A");
        return false;
    }
    ret = pn5180_setRF_on(pn5180);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to turn RF on for 14443A");
        return false;
    }
    return true;
}

/*
static void showIRQStatus(uint32_t irqStatus)
{
    printf("IRQ-Status 0x");
    printf("%08" PRIX32, irqStatus);
    printf(": [ ");
    if (irqStatus & (1 << 0)) printf("RQ ");
    if (irqStatus & (1 << 1)) printf("TX ");
    if (irqStatus & (1 << 2)) printf("IDLE ");
    if (irqStatus & (1 << 3)) printf("MODE_DETECTED ");
    if (irqStatus & (1 << 4)) printf("CARD_ACTIVATED ");
    if (irqStatus & (1 << 5)) printf("STATE_CHANGE ");
    if (irqStatus & (1 << 6)) printf("RFOFF_DET ");
    if (irqStatus & (1 << 7)) printf("RFON_DET ");
    if (irqStatus & (1 << 8)) printf("TX_RFOFF ");
    if (irqStatus & (1 << 9)) printf("TX_RFON ");
    if (irqStatus & (1 << 10)) printf("RF_ACTIVE_ERROR ");
    if (irqStatus & (1 << 11)) printf("TIMER0 ");
    if (irqStatus & (1 << 12)) printf("TIMER1 ");
    if (irqStatus & (1 << 13)) printf("TIMER2 ");
    if (irqStatus & (1 << 14)) printf("RX_SOF_DET ");
    if (irqStatus & (1 << 15)) printf("RX_SC_DET ");
    if (irqStatus & (1 << 16)) printf("TEMPSENS_ERROR ");
    if (irqStatus & (1 << 17)) printf("GENERAL_ERROR ");
    if (irqStatus & (1 << 18)) printf("HV_ERROR ");
    if (irqStatus & (1 << 19)) printf("LPCD ");
    printf("]\n");
}
*/
static bool pn5180_14443_sendREQA(pn5180_t *pn5180, uint8_t *atqa)
{
    // REQA is a 7-bit command (0x26)
    uint8_t cmd_buf[1] = {0x26};

    pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
    pn5180_disable_crc(pn5180);
    if (!pn5180_sendData(pn5180, cmd_buf, 1, 7)) {
        ESP_LOGE(TAG, "Failed to send REQA command");
        return false;
    }

    // Wait for ATQA response (RX) or command completion (IDLE)
    uint32_t irqStatus = 0;
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | IDLE_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "REQA ATQA", &irqStatus)) {
        ESP_LOGD(TAG, "No response to REQA (no cards in IDLE state)");
        return false;
    }

    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
        return false;
    }

    // Read ATQA (2 bytes)
    uint16_t rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen > 0) {
        if (!pn5180_readData(pn5180, rxLen, atqa)) {
            ESP_LOGE(TAG, "Failed to read ATQA from FIFO");
            return false;
        }
        ESP_LOGD(TAG, "REQA Success, ATQA: 0x%02X%02X", atqa[0], atqa[1]);
    }
    pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
    return (rxLen > 0);
}

static bool pn5180_14443_sendWUPA(pn5180_t *pn5180, uint8_t *atqa)
{
    // WUPA is a 7-bit command (0x52)
    uint8_t cmd_buf[1] = {0x52};

    pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
    pn5180_disable_crc(pn5180);
    if (!pn5180_sendData(pn5180, cmd_buf, 1, 7)) {
        ESP_LOGE(TAG, "Failed to send WUPA command");
        return false;
    }

    // Wait for ATQA response (RX) or command completion (IDLE)
    uint32_t irqStatus = 0;
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | IDLE_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "WUPA ATQA", &irqStatus)) {
        ESP_LOGD(TAG, "No response to WUPA");
        return false;
    }

    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
        return false;
    }

    // Read ATQA (2 bytes)
    uint16_t rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen > 0) {
        if (!pn5180_readData(pn5180, rxLen, atqa)) {
            ESP_LOGE(TAG, "Failed to read ATQA from FIFO");
            return false;
        }
        ESP_LOGD(TAG, "WUPA Success, ATQA: 0x%02X%02X", atqa[0], atqa[1]);
    }

    pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
    return (rxLen > 0);
}

static bool prepare_14443A_activation(pn5180_t *pn5180)
{
    if (!pn5180_14443_setupRF(pn5180)) {
        ESP_LOGE(TAG, "Failed to setup RF for 14443A activation");
        return false;
    }
    // clear MFC_CRYPTO_ON bit to disable MIFARE Crypto1
    if (!pn5180_writeRegisterWithAndMask(pn5180, SYSTEM_CONFIG, 0xFFFFFFBF)) {
        ESP_LOGE(TAG, "Failed to configure SYSTEM_CONFIG for 14443A activation");
        return false;
    }
    pn5180_disable_crc(pn5180);
    // Begin transceive and wait for WaitTransmit state
    if (!pn5180_begin_transceive(pn5180)) {
        ESP_LOGE(TAG, "Failed to enter transceive mode");
        return false;
    }
    pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
    return true;
}

static bool pn5180_14443_mifareHalt(pn5180_t *pn5180)
{
    // CRC on TX
    pn5180_enable_tx_crc(pn5180);
    // no CRC on RX
    pn5180_disable_rx_crc(pn5180);
    uint8_t cmd_buf[2];
    cmd_buf[0] = 0x50; // MIFARE Halt command
    cmd_buf[1] = 0x00;
    ESP_LOGD(TAG, "Sending MIFARE Halt command");
    bool ret = pn5180_sendData(pn5180, cmd_buf, 2, 0x00);
    if (ret) {
        uint32_t mask = TX_IRQ_STAT | IDLE_IRQ_STAT | GENERAL_ERROR_IRQ_STAT;
        uint32_t irqStatus;
        ret = pn5180_wait_for_irq(pn5180, mask, "HLTA Transmission", &irqStatus);
        if (!ret) {
            ESP_LOGE(TAG, "Timeout waiting for HLTA response");
        } else if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
            ESP_LOGE(TAG, "General error during HLTA");
            ret = false;
        }
    }
    // disable CRC for discovery mode
    pn5180_disable_crc(pn5180);
    pn5180_set_transceiver_idle(pn5180);
    return ret;
}

static bool pn5180_14443_sendSelect(pn5180_t *pn5180, int cascade_level, uint8_t *level_data, uint8_t *sak)
{
    pn5180_enable_crc(pn5180);
    uint8_t cmd_buf[7];
    cmd_buf[0] = 0x93 + ((cascade_level - 1) * 2); // 0x93, 0x95, 0x97 for cascade levels 1,2,3
    cmd_buf[1] = 0x70;                             // NVB = 0x70 (full 5 bytes)
    memcpy(&cmd_buf[2], level_data, 5);            // Copy UID CLn + BCC
    ESP_LOGD(TAG, "Sending Select command %d", cascade_level);
    if (!pn5180_sendData(pn5180, cmd_buf, 7, 0x00)) {
        pn5180_disable_crc(pn5180);
        ESP_LOGE(TAG, "Failed to send Select command %d", cascade_level);
        return false;
    }
    uint32_t irqStatus;
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "Select response", &irqStatus)) {
        pn5180_disable_crc(pn5180);
        ESP_LOGE(TAG, "Timeout waiting for Select response at level %d", cascade_level);
        return false;
    }
    // Check for Protocol/CRC errors
    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        ESP_LOGE(TAG, "General error during Select (possibly CRC mismatch)");
        pn5180_clearIRQStatus(pn5180, 0xffffffff);
        pn5180_disable_crc(pn5180);
        return false;
    }
    uint32_t rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen != 1) {
        ESP_LOGE(TAG, "SAK frame error: expected 1 byte, got %d", rxLen);
        pn5180_clearIRQStatus(pn5180, 0xffffffff);
        pn5180_disable_crc(pn5180);
        return false;
    }

    if (!pn5180_readData(pn5180, 1, sak)) {
        ESP_LOGE(TAG, "Failed to read SAK");
        pn5180_clearIRQStatus(pn5180, 0xffffffff);
        pn5180_disable_crc(pn5180);
        return false;
    }

    pn5180_clearIRQStatus(pn5180, 0xffffffff);
    pn5180_disable_crc(pn5180);
    return true;
}

// Helper function to resolve collisions in anticollision sequence
static bool pn5180_14443_resolve_collision(pn5180_t *pn5180, uint8_t cascadeLevel, uint8_t sel, uint8_t collisionPos,
                                           uint8_t rxLen, uint8_t *active_uid, uint8_t *temp_uid, uint8_t *uidLen)
{
    // Force the initial collision bit to 1 (choose the higher UID branch)
    uint8_t byte_idx = collisionPos / 8;
    uint8_t bit_idx  = collisionPos % 8;
    active_uid[byte_idx] |= (1 << bit_idx);

    uint8_t  known_bits         = collisionPos + 1;
    uint8_t  collision_attempts = 0;
    uint32_t irqStatus;
    uint8_t  cmd_buf[12];

    while (known_bits < 32 && collision_attempts < 64) {
        collision_attempts++;

        // Calculate NVB with +2 for SEL and NVB header bytes
        uint8_t bytes_count       = known_bits / 8;
        uint8_t bits_in_last_byte = known_bits % 8;
        uint8_t current_nvb       = ((bytes_count + 2) << 4) | bits_in_last_byte;

        ESP_LOGD(TAG, "Collision retry %d: known_bits=%d, NVB=0x%02X", collision_attempts, known_bits, current_nvb);

        // Re-force the collision bit (may have been overwritten by new data reads)
        uint8_t forced_byte_idx = (known_bits - 1) / 8;
        uint8_t forced_bit_idx  = (known_bits - 1) % 8;
        active_uid[forced_byte_idx] |= (1 << forced_bit_idx);

        // Build command: SEL + NVB + known UID bits
        cmd_buf[0] = sel;
        cmd_buf[1] = current_nvb;

        if (bytes_count > 0) {
            memcpy(&cmd_buf[2], active_uid, bytes_count);
        }

        // Mask partial byte
        if (bits_in_last_byte > 0) {
            uint8_t mask             = (1 << bits_in_last_byte) - 1;
            cmd_buf[2 + bytes_count] = active_uid[bytes_count] & mask;
        }

        int cmd_len = 2 + bytes_count + (bits_in_last_byte > 0 ? 1 : 0);

        // Send anticollision command
        if (!pn5180_sendData(pn5180, cmd_buf, cmd_len, bits_in_last_byte)) {
            ESP_LOGE(TAG, "Failed to send anticollision retry at level %d", cascadeLevel);
            return false;
        }

        // Wait for response
        if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT | IDLE_IRQ_STAT, "collision retry",
                          &irqStatus)) {
            ESP_LOGE(TAG, "Timeout in collision retry at level %d", cascadeLevel);
            return false;
        }

        // Check for collision
        if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
            uint32_t newRxStatus;
            if (!pn5180_readRegister(pn5180, RX_STATUS, &newRxStatus)) {
                ESP_LOGE(TAG, "Failed to read RX_STATUS in collision retry at level %d", cascadeLevel);
                pn5180_clearIRQStatus(pn5180, 0xffffffff);
                return false;
            }

            if (newRxStatus & (RX_COLLISION_DETECTED | RX_PROTOCOL_ERROR | RX_DATA_INTEGRITY_ERROR)) {
                // Still colliding - extract new position and retry
                uint8_t  newCollisionPos = (newRxStatus >> RX_COLL_POS_START) & RX_COLL_POS_MASK;
                uint16_t newRxLen        = pn5180_rxBytesReceived(pn5180);

                if (newRxLen > 0 && newRxLen <= 5) {
                    if (!pn5180_readData(pn5180, newRxLen, active_uid)) {
                        ESP_LOGE(TAG, "Failed to read partial UID in retry at level %d", cascadeLevel);
                        pn5180_clearIRQStatus(pn5180, 0xffffffff);
                        return false;
                    }
                }

                pn5180_clearIRQStatus(pn5180, 0xffffffff);

                // Force new collision bit and continue
                uint8_t new_byte_idx = newCollisionPos / 8;
                uint8_t new_bit_idx  = newCollisionPos % 8;
                active_uid[new_byte_idx] |= (1 << new_bit_idx);
                known_bits = newCollisionPos + 1;
                continue;
            }
        }

        // No collision - read complete response
        rxLen = pn5180_rxBytesReceived(pn5180);
        if (rxLen == 0 || rxLen > 10) {
            pn5180_clearIRQStatus(pn5180, 0xffffffff);
            ESP_LOGE(TAG, "Invalid response length %d after collision resolution", rxLen);
            return false;
        }

        if (!pn5180_readData(pn5180, rxLen, cmd_buf)) {
            pn5180_clearIRQStatus(pn5180, 0xffffffff);
            ESP_LOGE(TAG, "Failed to read UID+BCC after collision resolution at level %d", cascadeLevel);
            return false;
        }

        pn5180_clearIRQStatus(pn5180, 0xffffffff);

        // Validate BCC and return
        if (rxLen == 5) {
            uint8_t bcc = cmd_buf[0] ^ cmd_buf[1] ^ cmd_buf[2] ^ cmd_buf[3];
            if (bcc != cmd_buf[4]) {
                ESP_LOGE(TAG, "BCC check failed after resolution at level %d", cascadeLevel);
                return false;
            }
            *uidLen = 4;
            memcpy(temp_uid, cmd_buf, 5);
            return true;
        }
    }

    ESP_LOGE(TAG, "Failed to resolve collision at level %d after %d attempts", cascadeLevel, collision_attempts);
    return false;
}

static bool pn5180_14443_anticollision_level(pn5180_t *pn5180, uint8_t cascadeLevel, uint8_t *temp_uid, uint8_t *uidLen)
{
    uint8_t sel = 0x93 + (2 * (cascadeLevel - 1));
    uint8_t nvb = 0x20;
    uint8_t cmd_buf[12];
    cmd_buf[0] = sel;
    cmd_buf[1] = nvb;

    ESP_LOGD(TAG, "Sending Anti-collision command for cascade level %d", cascadeLevel);
    if (!pn5180_sendData(pn5180, cmd_buf, 2, 0)) {
        ESP_LOGE(TAG, "Failed to send Anti-collision command at level %d", cascadeLevel);
        return false;
    }

    // Wait for response
    uint32_t irqStatus;
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT | IDLE_IRQ_STAT, "anticollision response",
                      &irqStatus)) {
        ESP_LOGE(TAG, "Timeout waiting for anticollision response at level %d", cascadeLevel);
        return false;
    }

    // Get response length
    uint16_t rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen == 0 || rxLen > 10) {
        pn5180_clearIRQStatus(pn5180, 0xffffffff);
        ESP_LOGE(TAG, "Invalid response length %d at level %d", rxLen, cascadeLevel);
        return false;
    }

    // Read response
    if (!pn5180_readData(pn5180, rxLen, cmd_buf)) {
        pn5180_clearIRQStatus(pn5180, 0xffffffff);
        ESP_LOGE(TAG, "Failed to read response at level %d", cascadeLevel);
        return false;
    }

    pn5180_clearIRQStatus(pn5180, 0xffffffff);

    // Check for collision
    if ((irqStatus & GENERAL_ERROR_IRQ_STAT) == 0) {
        // No collision - validate and return
        if (rxLen != 5) {
            ESP_LOGD(TAG, "Unexpected response length %d at level %d (expected 5)", rxLen, cascadeLevel);
            return false;
        }

        uint8_t bcc = cmd_buf[0] ^ cmd_buf[1] ^ cmd_buf[2] ^ cmd_buf[3];
        if (bcc != cmd_buf[4]) {
            ESP_LOGE(TAG, "BCC check failed at level %d", cascadeLevel);
            return false;
        }

        *uidLen = 4;
        memcpy(temp_uid, cmd_buf, 5);
        return true;
    }

    // Collision detected - resolve it
    uint32_t rxStatus;
    if (!pn5180_readRegister(pn5180, RX_STATUS, &rxStatus) ||
        0 == (rxStatus & (RX_COLLISION_DETECTED | RX_PROTOCOL_ERROR | RX_DATA_INTEGRITY_ERROR))) {
        ESP_LOGE(TAG, "Failed to read RX_STATUS at level %d", cascadeLevel);
        return false;
    }

    uint8_t collisionPos = (rxStatus >> RX_COLL_POS_START) & RX_COLL_POS_MASK;
    ESP_LOGD(TAG, "Collision at level %d, bit position %d", cascadeLevel, collisionPos);

    // Copy received partial UID
    uint8_t active_uid[5] = {0};
    if (rxLen > 0 && rxLen <= 5) {
        memcpy(active_uid, cmd_buf, rxLen);
    }

    // Resolve collision iteratively
    return pn5180_14443_resolve_collision(pn5180, cascadeLevel, sel, collisionPos, rxLen, active_uid, temp_uid, uidLen);
}

static bool pn5180_14443_resolve_full_uid_cascade(pn5180_t *pn5180, uint8_t *full_uid, uint8_t *full_uid_len)
{
    uint8_t cascade_level = 1;
    *full_uid_len         = 0;
    pn5180_disable_crc(pn5180);
    while (cascade_level <= 3) {
        uint8_t level_data[5]; // UID + BCC
        uint8_t len;
        if (!pn5180_14443_anticollision_level(pn5180, cascade_level, level_data, &len)) {
            ESP_LOGD(TAG, "Anticollision failed at level %d", cascade_level);
            return false;
        }
        uint8_t sak;
        if (!pn5180_14443_sendSelect(pn5180, cascade_level, level_data, &sak)) {
            ESP_LOGE(TAG, "Select command failed at level %d", cascade_level);
            return false;
        }
        // SAK Bit 3 (0x04) indicates if another cascade level follows
        if (sak & 0x04) {
            // It's a 7 or 10 byte UID. Skip CT (0x88) and take 3 bytes.
            if (level_data[0] != 0x88) {
                ESP_LOGE(TAG, "Protocol Error: Expected Cascade Tag 0x88, got 0x%02X", level_data[0]);
                return false;
            }
            memcpy(&full_uid[*full_uid_len], &level_data[1], 3);
            *full_uid_len += 3;
            cascade_level++;
        } else {
            // Final level. Take all 4 bytes.
            memcpy(&full_uid[*full_uid_len], level_data, 4);
            *full_uid_len += 4;
            return true;
        }
    }
    return false;
}

static nfc_uids_array_t *pn5180_14443_get_all_uids(pn5180_t *pn5180)
{
    nfc_uids_array_t *uids = NULL;
    uint8_t card_count = 0;
    bool    need_break = false;
    prepare_14443A_activation(pn5180);
    while (card_count < 14 && !need_break) {
        uint8_t atqa[2];
        if (!pn5180_14443_sendREQA(pn5180, atqa)) {
            ESP_LOGI(TAG, "No more cards found.");
            break;
        }

        uint8_t full_uid[12];
        uint8_t full_uid_len = 0;
        if (pn5180_14443_resolve_full_uid_cascade(pn5180, full_uid, &full_uid_len)) {
            ESP_LOGI(TAG, "Found Card %d: UID Len %d", ++card_count, full_uid_len);
            if (uids == NULL) {
                uids = calloc(1, sizeof(nfc_uids_array_t));
                if (uids == NULL) {
                    ESP_LOGE(TAG, "Memory allocation failed for UIDs");
                    need_break = true;
                } else {
                    uids->uids_count         = 1;
                    uids->uids[0].uid_length = full_uid_len;
                    memcpy(uids->uids[0].uid, full_uid, full_uid_len);
                }
            } else {
                nfc_uids_array_t *new_uids =
                    realloc(uids, sizeof(nfc_uids_array_t) + (uids->uids_count * sizeof(nfc_uid_t)));
                if (new_uids == NULL) {
                    ESP_LOGE(TAG, "Memory allocation failed for UIDs");
                    need_break = true;
                } else {
                    uids                                    = new_uids;
                    uids->uids[uids->uids_count].uid_length = full_uid_len;
                    memcpy(uids->uids[uids->uids_count].uid, full_uid, full_uid_len);
                    uids->uids_count++;
                }
            }
            pn5180_14443_mifareHalt(pn5180);
        } else {
            break;
        }
    }
    return uids;
}

static bool pn5180_14443_select_by_uid(pn5180_t *pn5180, nfc_uid_t *uid)
{
    uint8_t current_level = 1;
    uint8_t uid_offset    = 0;
    uint8_t sak           = 0;
    uint8_t level_data[5]; // 4 data bytes + 1 BCC
    uint8_t atqa[2];
    prepare_14443A_activation(pn5180);
    if (!pn5180_14443_sendWUPA(pn5180, atqa)) {
        ESP_LOGE(TAG, "No card in field for direct selection");
        return false;
    }

    while (current_level <= 3) {
        // Validate we have enough UID bytes remaining
        if (uid_offset >= uid->uid_length) {
            ESP_LOGE(TAG, "UID offset %d exceeds UID length %d at level %d", uid_offset, uid->uid_length,
                     current_level);
            return false;
        }

        // Construct the 4-byte UID segment for this level
        if (uid->uid_length > 4 && current_level < 3 && (uid->uid_length - uid_offset) > 4) {
            // For 7 or 10 byte UIDs, we need the Cascade Tag (0x88)
            level_data[0] = 0x88;
            memcpy(&level_data[1], &uid->uid[uid_offset], 3);
            uid_offset += 3;
        } else {
            // Final segment (or 4-byte UID)
            uint8_t remaining = uid->uid_length - uid_offset;
            if (remaining < 4) {
                ESP_LOGE(TAG, "Insufficient UID bytes at level %d: need 4, have %d", current_level, remaining);
                return false;
            }
            memcpy(level_data, &uid->uid[uid_offset], 4);
            uid_offset += 4;
        }

        // Calculate BCC for this level's segment
        level_data[4] = level_data[0] ^ level_data[1] ^ level_data[2] ^ level_data[3];

        // 2. Perform Selection (NVB = 0x70)
        if (!pn5180_14443_sendSelect(pn5180, current_level, level_data, &sak)) {
            ESP_LOGE(TAG, "Direct Select failed at Level %d", current_level);
            return false;
        }

        // 3. Check if UID is complete
        if (!(sak & 0x04)) {
            ESP_LOGI(TAG, "Card successfully selected via direct path!");
            return true;
        }

        current_level++;
    }
    return false;
}

static bool pn5180_14443_mifareBlockRead(pn5180_t *pn5180, uint8_t blockno, uint8_t *buffer)
{
    pn5180_disable_crc(pn5180);
    uint8_t cmd_buf[2];
    cmd_buf[0] = 0x30; // MIFARE Read command
    cmd_buf[1] = blockno;
    if (!pn5180_sendData(pn5180, cmd_buf, 2, 0x00)) {
        ESP_LOGE(TAG, "Failed to send MIFARE Read command for block %d", blockno);
        pn5180_enable_crc(pn5180);
        return false;
    }

    uint32_t irqStatus;
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "MIFARE Read", &irqStatus)) {
        ESP_LOGE(TAG, "Timeout waiting for MIFARE block %d read response", blockno);
        pn5180_enable_crc(pn5180);
        return false;
    }

    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        ESP_LOGE(TAG, "Error during MIFARE block %d read", blockno);
        pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
        pn5180_enable_crc(pn5180);
        return false;
    }

    uint16_t rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen != 16) {
        ESP_LOGE(TAG, "MIFARE block %d read returned incorrect length: %d", blockno, rxLen);
        pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
        pn5180_enable_crc(pn5180);
        return false;
    }

    if (!pn5180_readData(pn5180, 16, buffer)) {
        ESP_LOGE(TAG, "Failed to read MIFARE block %d data", blockno);
        pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
        pn5180_enable_crc(pn5180);
        return false;
    }

    pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
    pn5180_enable_crc(pn5180);
    return true;
}

static int pn5180_14443_mifareBlockWrite(pn5180_t *pn5180, uint8_t blockno, const uint8_t *buffer)
{
    pn5180_disable_crc(pn5180);
    uint8_t cmd_buf[2];
    cmd_buf[0] = 0xA0; // MIFARE Write command
    cmd_buf[1] = blockno;
    if (!pn5180_sendData(pn5180, cmd_buf, 2, 0x00)) {
        ESP_LOGE(TAG, "Failed to send MIFARE Write command for block %d", blockno);
        pn5180_enable_crc(pn5180);
        return -1;
    }

    uint32_t irqStatus;
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "MIFARE Write ACK", &irqStatus)) {
        ESP_LOGE(TAG, "Timeout waiting for MIFARE block %d write ACK", blockno);
        pn5180_enable_crc(pn5180);
        return -1;
    }

    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        ESP_LOGE(TAG, "Error during MIFARE block %d write ACK", blockno);
        pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
        pn5180_enable_crc(pn5180);
        return -1;
    }

    uint16_t rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen != 1) {
        ESP_LOGE(TAG, "MIFARE block %d write ACK returned incorrect length: %d", blockno, rxLen);
        pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
        pn5180_enable_crc(pn5180);
        return -2;
    }

    uint8_t ack;
    if (!pn5180_readData(pn5180, 1, &ack)) {
        ESP_LOGE(TAG, "Failed to read MIFARE block %d write ACK", blockno);
        pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
        pn5180_enable_crc(pn5180);
        return -2;
    }

    pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);

    if ((ack & 0x0F) != 0x0A) {
        ESP_LOGE(TAG, "MIFARE block %d write NACK received: 0x%02X", blockno, ack);
        pn5180_enable_crc(pn5180);
        return -3;
    }

    // Send 16 bytes of data to write
    if (!pn5180_sendData(pn5180, buffer, 16, 0x00)) {
        ESP_LOGE(TAG, "Failed to send MIFARE block %d data for writing", blockno);
        pn5180_enable_crc(pn5180);
        return -4;
    }

    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "MIFARE Write Final ACK", &irqStatus)) {
        ESP_LOGE(TAG, "Timeout waiting for MIFARE block %d write final ACK", blockno);
        pn5180_enable_crc(pn5180);
        return -5;
    }

    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        ESP_LOGE(TAG, "Error during MIFARE block %d write final ACK", blockno);
        pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
        pn5180_enable_crc(pn5180);
        return -5;
    }

    rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen != 1) {
        ESP_LOGE(TAG, "MIFARE block %d write final ACK returned incorrect length: %d", blockno, rxLen);
        pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
        pn5180_enable_crc(pn5180);
        return -6;
    }

    if (!pn5180_readData(pn5180, 1, &ack)) {
        ESP_LOGE(TAG, "Failed to read MIFARE block %d write final ACK", blockno);
        pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
        pn5180_enable_crc(pn5180);
        return -7;
    }

    pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);

    if ((ack & 0x0F) != 0x0A) {
        ESP_LOGE(TAG, "MIFARE block %d write final NACK received: 0x%02X", blockno, ack);
        pn5180_enable_crc(pn5180);
        return -8;
    }

    pn5180_enable_crc(pn5180);
    return 0;
}
