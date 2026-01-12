#include "pn5180-14443.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <string.h>

static const char *TAG = "pn5180-14443";

static nfc_uids_array_t *pn5180_14443_get_all_uids(pn5180_t *pn5180);

static bool pn5180_14443_select_by_uid(pn5180_t *pn5180, nfc_uid_t *uid);
static bool pn5180_14443_detect_ultralight_variant(pn5180_t *pn5180, mifare_type_t *subtype, int *blocks_count);
static void pn5180_14443_detect_desfire_capacity(pn5180_t *pn5180, int *blocks_count);
static bool pn5180_14443_mifareBlockRead(pn5180_t *pn5180, int blockno, uint8_t *buffer, size_t buffer_len);
static int  pn5180_14443_mifareBlockWrite(pn5180_t *pn5180, int blockno, const uint8_t *buffer);
static bool pn5180_14443_mifareHalt(pn5180_t *pn5180);
static bool pn5180_14443_setupRF(pn5180_t *pn5180);
static bool _pn5180_14443_detect_card_type_and_capacity( //
    pn5180_t  *pn5180,                                   //
    nfc_uid_t *uid,                                      //
    int       *blocks_count,                             //
    int       *block_size                                //
);

static bool _pn5180_14443_setupRF(pn5180_proto_t *proto)
{
    return pn5180_14443_setupRF(proto->pn5180);
}

static nfc_uids_array_t *_pn5180_14443_get_all_uids(pn5180_proto_t *proto)
{
    return pn5180_14443_get_all_uids(proto->pn5180);
}

static bool _pn5180_14443_select_by_uid(pn5180_proto_t *proto, nfc_uid_t *uid)
{
    return pn5180_14443_select_by_uid(proto->pn5180, uid);
}

static bool _pn5180_14443_mifareBlockRead(pn5180_proto_t *proto, int blockno, uint8_t *buffer, size_t buffer_len)
{
    return pn5180_14443_mifareBlockRead(proto->pn5180, blockno, buffer, buffer_len);
}

static int _pn5180_14443_mifareBlockWrite(pn5180_proto_t *proto, int blockno, const uint8_t *buffer)
{
    return pn5180_14443_mifareBlockWrite(proto->pn5180, blockno, buffer);
}

// Wrapper for protocol interface
static bool _pn5180_14443_halt(pn5180_proto_t *proto)
{
    return pn5180_14443_mifareHalt(proto->pn5180);
}

static bool _pn5180_14443_authenticate( //
    pn5180_proto_t  *proto,             //
    const uint8_t   *key,               //
    uint8_t          keyType,           //
    const nfc_uid_t *uid,               //
    int              blockno            //
)
{
    // MIFARE authentication for already selected card
    // subtype indicates card type (Classic 1K/4K, Plus, etc.)
    // keyType: 0x60 for Key A, 0x61 for Key B

    if (uid->subtype == PN5180_MIFARE_ULTRALIGHT || uid->subtype == PN5180_MIFARE_ULTRALIGHT_C ||
        uid->subtype == PN5180_MIFARE_ULTRALIGHT_EV1 || uid->subtype == PN5180_MIFARE_NTAG213 ||
        uid->subtype == PN5180_MIFARE_NTAG215 || uid->subtype == PN5180_MIFARE_NTAG216) {
        // Ultralight variants don't require MIFARE authentication
        return true;
    }

    if (uid->subtype == PN5180_MIFARE_DESFIRE) {
        // DESFire uses ISO 14443-4 authentication, not MIFARE Crypto1
        return true;
    }

    // MIFARE Classic/Plus authentication with Crypto1
    // Extract last 4 bytes of UID for authentication
    // - 4-byte UIDs: use all 4 bytes
    // - 7-byte UIDs: use bytes [3:6] (last 4 bytes)
    // - 10-byte UIDs: use bytes [6:9] (last 4 bytes)
    const uint8_t *uid_for_auth;
    if (uid->uid_length <= 4) {
        uid_for_auth = uid->uid;
    } else if (uid->uid_length == 7) {
        uid_for_auth = &uid->uid[3]; // Last 4 bytes of 7-byte UID
    } else if (uid->uid_length == 10) {
        uid_for_auth = &uid->uid[6]; // Last 4 bytes of 10-byte UID
    } else {
        ESP_LOGE(TAG, "Invalid UID length %d for MIFARE authentication", uid->uid_length);
        return false;
    }

    ESP_LOGD(
        TAG,
        "Authenticating: KeyType=0x%02X Block=%d Key=[%02X %02X %02X %02X %02X %02X] UID_Auth=[%02X %02X %02X %02X]",
        keyType, blockno, key[0], key[1], key[2], key[3], key[4], key[5], uid_for_auth[0], uid_for_auth[1],
        uid_for_auth[2], uid_for_auth[3]);

    // Send AUTH command immediately - DO NOT manipulate registers between SELECT and AUTH
    // The working reference implementation sends AUTH with no register touches
    int16_t auth_result = pn5180_mifareAuthenticate(proto->pn5180, (uint8_t)blockno, key, keyType, uid_for_auth);

    if (auth_result < 0) {
        ESP_LOGE(TAG, "MIFARE authentication failed with error code %d", auth_result);
        return false;
    }

    // Check authentication status (0x00 = success)
    if (auth_result != 0x00) {
        ESP_LOGE(TAG, "MIFARE authentication rejected by card (status: 0x%02X)", auth_result);
        // On failed authentication, disable Crypto1 and reset to clean state
        pn5180_writeRegisterWithAndMask(proto->pn5180, SYSTEM_CONFIG, SYSTEM_CONFIG_CLEAR_CRYPTO_MASK); // Clear MFC_CRYPTO_ON
        pn5180_disable_crc(proto->pn5180);
        return false;
    }

    ESP_LOGD(TAG, "MIFARE authentication successful for block %d", blockno);

    pn5180_delay_ms(1);

    // Enable CRC for subsequent authenticated read/write operations
    pn5180_enable_crc(proto->pn5180);
    return true;
}

pn5180_proto_t *pn5180_14443_init(pn5180_t *pn5180)
{
    pn5180_proto_t *proto = (pn5180_proto_t *)calloc(1, sizeof(pn5180_proto_t));
    if (proto == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for PN5180 14443 protocol");
        return NULL;
    }
    proto->pn5180                        = pn5180;
    proto->setup_rf                      = _pn5180_14443_setupRF;
    proto->get_all_uids                  = _pn5180_14443_get_all_uids;
    proto->select_by_uid                 = _pn5180_14443_select_by_uid;
    proto->block_read                    = _pn5180_14443_mifareBlockRead;
    proto->block_write                   = _pn5180_14443_mifareBlockWrite;
    proto->authenticate                  = _pn5180_14443_authenticate;
    proto->detect_card_type_and_capacity = _pn5180_14443_detect_card_type_and_capacity;
    proto->halt                          = _pn5180_14443_halt;
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

static bool pn5180_14443_sendREQA(pn5180_t *pn5180, uint8_t *atqa)
{
    // REQA is a 7-bit command (0x26)
    uint8_t cmd_buf[1] = {0x26};

    // Clear MFC_CRYPTO_ON bit to ensure clean state for new card discovery
    pn5180_writeRegisterWithAndMask(pn5180, SYSTEM_CONFIG, SYSTEM_CONFIG_CLEAR_CRYPTO_MASK);
    pn5180_clearAllIRQs(pn5180);
    pn5180_disable_crc(pn5180);
    ESP_LOGD(TAG, "Sending REQA: 0x%02X (7 bits)", cmd_buf[0]);
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
        pn5180_clearAllIRQs(pn5180);
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
    pn5180_clearAllIRQs(pn5180);
    return (rxLen > 0);
}

static bool pn5180_14443_sendWUPA(pn5180_t *pn5180, uint8_t *atqa)
{
    // WUPA is a 7-bit command (0x52)
    uint8_t cmd_buf[1] = {0x52};

    // Clear MFC_CRYPTO_ON bit to ensure clean state
    // Don't manually set transceive state - let pn5180_sendData() handle it
    pn5180_writeRegisterWithAndMask(pn5180, SYSTEM_CONFIG, SYSTEM_CONFIG_CLEAR_CRYPTO_MASK);
    pn5180_clearAllIRQs(pn5180);
    pn5180_disable_crc(pn5180);
    ESP_LOGD(TAG, "Sending WUPA: 0x%02X (7 bits)", cmd_buf[0]);
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
        pn5180_clearAllIRQs(pn5180);
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

    pn5180_clearAllIRQs(pn5180);
    return (rxLen > 0);
}

static bool prepare_14443A_activation(pn5180_t *pn5180)
{
    if (!pn5180_14443_setupRF(pn5180)) {
        ESP_LOGE(TAG, "Failed to setup RF for 14443A activation");
        return false;
    }
    
    // Full transceiver reset to clear both software and hardware Crypto1 state
    // This matches the working log initialization sequence:
    
    // 1. Clear MFC_CRYPTO_ON software bit (bit 6) only
    if (!pn5180_writeRegisterWithAndMask(pn5180, SYSTEM_CONFIG, SYSTEM_CONFIG_CLEAR_CRYPTO_MASK)) {
        ESP_LOGE(TAG, "Failed to clear MFC_CRYPTO_ON");
        return false;
    }
    
    // 2. Disable TX/RX CRC
    pn5180_disable_crc(pn5180);
    
    // 3. Force transceiver to IDLE state (clears bits [2:0])
    if (!pn5180_writeRegisterWithAndMask(pn5180, SYSTEM_CONFIG, SYSTEM_CONFIG_CLEAR_TX_MODE_MASK)) {
        ESP_LOGE(TAG, "Failed to set transceiver to IDLE");
        return false;
    }
    
    // 4. Set to Transceive state
    if (!pn5180_writeRegisterWithOrMask(pn5180, SYSTEM_CONFIG, SYSTEM_CONFIG_TX_MODE_TRANSCEIVE)) {
        ESP_LOGE(TAG, "Failed to set Transceive state");
        return false;
    }
    
    // 5. Clear all IRQ flags
    pn5180_clearAllIRQs(pn5180);
    
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
    ESP_LOGD(TAG, "HALT data: 0x%02X 0x%02X", cmd_buf[0], cmd_buf[1]);
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
    // Clear MFC_CRYPTO_ON bit to disable MIFARE Crypto1 after halt
    pn5180_writeRegisterWithAndMask(pn5180, SYSTEM_CONFIG, SYSTEM_CONFIG_CLEAR_CRYPTO_MASK);
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
    ESP_LOGD(TAG, "SELECT data: %02X %02X %02X %02X %02X %02X %02X", 
             cmd_buf[0], cmd_buf[1], cmd_buf[2], cmd_buf[3], cmd_buf[4], cmd_buf[5], cmd_buf[6]);
    if (!pn5180_sendData(pn5180, cmd_buf, 7, 0x00)) {
        pn5180_disable_crc(pn5180);
        ESP_LOGE(TAG, "Failed to send Select command %d", cascade_level);
        return false;
    }
    uint32_t irqStatus;
    bool     got_response =
        pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "Select response", &irqStatus);
    pn5180_clearAllIRQs(pn5180);
    if (!got_response) {
        pn5180_disable_crc(pn5180);
        ESP_LOGE(TAG, "Timeout waiting for Select response at level %d", cascade_level);
        return false;
    }
    // Check for Protocol/CRC errors
    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        ESP_LOGE(TAG, "General error during Select (possibly CRC mismatch)");
        pn5180_disable_crc(pn5180);
        return false;
    }
    uint32_t rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen != 1) {
        ESP_LOGE(TAG, "SAK frame error: expected 1 byte, got %d", rxLen);
        pn5180_disable_crc(pn5180);
        return false;
    }

    if (!pn5180_readData(pn5180, 1, sak)) {
        ESP_LOGE(TAG, "Failed to read SAK");
        pn5180_disable_crc(pn5180);
        return false;
    }
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
        ESP_LOGD(TAG, "Collision retry: sending %d bytes, %d bits in last byte", cmd_len, bits_in_last_byte);
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
                pn5180_clearAllIRQs(pn5180);
                return false;
            }

            if (newRxStatus & (RX_COLLISION_DETECTED | RX_PROTOCOL_ERROR | RX_DATA_INTEGRITY_ERROR)) {
                // Still colliding - extract new position and retry
                uint8_t  newCollisionPos = (newRxStatus >> RX_COLL_POS_START) & RX_COLL_POS_MASK;
                uint16_t newRxLen        = pn5180_rxBytesReceived(pn5180);

                if (newRxLen > 0 && newRxLen <= 5) {
                    if (!pn5180_readData(pn5180, newRxLen, active_uid)) {
                        ESP_LOGE(TAG, "Failed to read partial UID in retry at level %d", cascadeLevel);
                        pn5180_clearAllIRQs(pn5180);
                        return false;
                    }
                }

                pn5180_clearAllIRQs(pn5180);

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
            pn5180_clearAllIRQs(pn5180);
            ESP_LOGE(TAG, "Invalid response length %d after collision resolution", rxLen);
            return false;
        }

        if (!pn5180_readData(pn5180, rxLen, cmd_buf)) {
            pn5180_clearAllIRQs(pn5180);
            ESP_LOGE(TAG, "Failed to read UID+BCC after collision resolution at level %d", cascadeLevel);
            return false;
        }

        pn5180_clearAllIRQs(pn5180);

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

static bool pn5180_14443_anticollision_level(pn5180_t *pn5180, uint8_t cascadeLevel, uint8_t temp_uid[5],
                                             uint8_t *uidLen)
{
    uint8_t sel = 0x93 + (2 * (cascadeLevel - 1));
    uint8_t nvb = 0x20;
    uint8_t cmd_buf[12];
    cmd_buf[0] = sel;
    cmd_buf[1] = nvb;

    ESP_LOGD(TAG, "Sending Anti-collision command for cascade level %d", cascadeLevel);
    ESP_LOGD(TAG, "Anti-collision: SEL=0x%02X NVB=0x%02X", sel, nvb);
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
        pn5180_clearAllIRQs(pn5180);
        ESP_LOGE(TAG, "Invalid response length %d at level %d", rxLen, cascadeLevel);
        return false;
    }

    // Read response
    if (!pn5180_readData(pn5180, rxLen, cmd_buf)) {
        pn5180_clearAllIRQs(pn5180);
        ESP_LOGE(TAG, "Failed to read response at level %d", cascadeLevel);
        return false;
    }

    pn5180_clearAllIRQs(pn5180);

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

static bool pn5180_14443_resolve_full_uid_cascade(pn5180_t *pn5180, uint8_t *full_uid, int8_t *full_uid_len,
                                                  uint8_t *sak)
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
        if (!pn5180_14443_sendSelect(pn5180, cascade_level, level_data, sak)) {
            ESP_LOGE(TAG, "Select command failed at level %d", cascade_level);
            return false;
        }
        // SAK Bit 3 (0x04) indicates if another cascade level follows
        if (*sak & 0x04) {
            // It's a 7 or 10 byte UID. Skip CT (0x88) and take 3 bytes.
            if (level_data[0] != 0x88) {
                ESP_LOGE(TAG, "Protocol Error: Expected Cascade Tag 0x88, got 0x%02X", level_data[0]);
                return false;
            }
            memcpy(&full_uid[*full_uid_len], &level_data[1], 3);
            *full_uid_len += 3;
            cascade_level++;
            // Disable CRC before next anticollision level
            pn5180_disable_crc(pn5180);
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
    nfc_uids_array_t *uids       = NULL;
    uint8_t           card_count = 0;
    bool              need_break = false;
    prepare_14443A_activation(pn5180);
    while (card_count < 14 && !need_break) {
        uint8_t atqa[2];
        if (!pn5180_14443_sendREQA(pn5180, atqa)) {
            ESP_LOGI(TAG, "No more cards found.");
            break;
        }

        uint8_t full_uid[12];
        int8_t  full_uid_len = 0;
        uint8_t sak;
        if (pn5180_14443_resolve_full_uid_cascade(pn5180, full_uid, &full_uid_len, &sak)) {
            ESP_LOGI(TAG, "Found Card %d: UID Len %d", ++card_count, full_uid_len);
            if (uids == NULL) {
                uids = calloc(1, sizeof(nfc_uids_array_t));
                if (uids == NULL) {
                    ESP_LOGE(TAG, "Memory allocation failed for UIDs");
                    need_break = true;
                } else {
                    uids->uids_count         = 1;
                    uids->uids[0].uid_length = full_uid_len;
                    uids->uids[0].sak        = sak;
                    uids->uids[0].subtype    = PN5180_MIFARE_UNKNOWN;
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
                    uids->uids[uids->uids_count].sak        = sak;
                    uids->uids[uids->uids_count].subtype    = PN5180_MIFARE_UNKNOWN;
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

/*
    Returns true if card required reselection
*/
static bool pn5180_14443_detect_ultralight_variant(pn5180_t *pn5180, mifare_type_t *subtype, int *blocks_count)
{
    uint8_t response[8];
    uint8_t get_version_cmd = 0x60;

    // Set defaults
    *subtype      = PN5180_MIFARE_ULTRALIGHT;
    *blocks_count = 16;

    // Attempt GET_VERSION command via RF transmission
    pn5180_enable_crc(pn5180);

    ESP_LOGD(TAG, "Sending GET_VERSION: 0x%02X", get_version_cmd);
    if (!pn5180_sendData(pn5180, &get_version_cmd, 1, 0)) {
        ESP_LOGD(TAG, "GET_VERSION send failed - assuming standard Ultralight");
        pn5180_disable_crc(pn5180);
        return true;
    }

    // Wait for card response
    uint32_t irqStatus;
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "GET_VERSION", &irqStatus)) {
        ESP_LOGD(TAG, "GET_VERSION timeout - assuming standard Ultralight");
        pn5180_clearAllIRQs(pn5180);
        pn5180_disable_crc(pn5180);
        return true;
    }

    // Check for errors
    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        ESP_LOGD(TAG, "GET_VERSION general error - assuming standard Ultralight");
        pn5180_clearAllIRQs(pn5180);
        pn5180_disable_crc(pn5180);
        return true;
    }

    // Read response
    uint16_t rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen < 8 || !pn5180_readData(pn5180, 8, response)) {
        ESP_LOGD(TAG, "GET_VERSION read failed (rxLen=%d) - assuming standard Ultralight", rxLen);
        pn5180_clearAllIRQs(pn5180);
        pn5180_disable_crc(pn5180);
        return true;
    }

    pn5180_clearAllIRQs(pn5180);
    pn5180_disable_crc(pn5180);

    // Extract and map storage size byte (response[6])
    uint8_t storage_size = response[6];

    switch (storage_size) {
    case 0x0B: // Ultralight EV1 48 bytes (20 pages)
        ESP_LOGD(TAG, "Detected MIFARE Ultralight EV1 (48 bytes, 20 pages)");
        *subtype      = PN5180_MIFARE_ULTRALIGHT_EV1;
        *blocks_count = 20;
        break;
    case 0x0E: // Ultralight EV1 128 bytes (41 pages)
        ESP_LOGD(TAG, "Detected MIFARE Ultralight EV1 (128 bytes, 41 pages)");
        *subtype      = PN5180_MIFARE_ULTRALIGHT_EV1;
        *blocks_count = 41;
        break;
    case 0x0F: // NTAG variant with ~142 bytes (45 pages)
        ESP_LOGD(TAG, "Detected NTAG variant (storage_size=0x0F, ~142 bytes, 45 pages)");
        *subtype      = PN5180_MIFARE_NTAG213;
        *blocks_count = 45;
        break;
    case 0x11: // NTAG213 180 bytes total (45 pages)
        ESP_LOGD(TAG, "Detected NTAG213 (180 bytes total, 45 pages)");
        *subtype      = PN5180_MIFARE_NTAG213;
        *blocks_count = 45;
        break;
    case 0x13: // NTAG215 540 bytes total (135 pages)
        ESP_LOGD(TAG, "Detected NTAG215 (540 bytes total, 135 pages)");
        *subtype      = PN5180_MIFARE_NTAG215;
        *blocks_count = 135;
        break;
    case 0x15: // NTAG216 924 bytes total (231 pages)
        ESP_LOGD(TAG, "Detected NTAG216 (924 bytes total, 231 pages)");
        *subtype      = PN5180_MIFARE_NTAG216;
        *blocks_count = 231;
        break;
    default:
        ESP_LOGD(TAG, "Unknown GET_VERSION storage size: 0x%02X - assuming standard Ultralight", storage_size);
        *subtype      = PN5180_MIFARE_ULTRALIGHT;
        *blocks_count = 16;
        break;
    }
    return false;
}

static void pn5180_14443_detect_desfire_capacity(pn5180_t *pn5180, int *blocks_count)
{
    // DESFire requires ISO 14443-4 Layer 4 activation (RATS protocol) before it responds to commands.
    // For now, default to 4KB (0x1A) rather than attempting GET_VERSION without proper Layer 4 setup.
    // TODO: Implement full ISO 14443-4 RATS handshake for proper capacity detection

    *blocks_count = 4096; // Default to 4KB DESFire
    ESP_LOGD(TAG, "DESFire capacity defaulting to 4KB (proper detection requires ISO 14443-4 RATS)");
}

static bool _pn5180_14443_detect_card_type_and_capacity( //
    pn5180_t  *pn5180,                                   //
    nfc_uid_t *uid,                                      //
    int       *blocks_count,                             //
    int       *block_size                                //
)
{
    bool need_reselection = false;
    // Determine card type from SAK
    uint8_t card_type = uid->sak & 0x7F;
    switch (card_type) {
    case 0x00: // MIFARE Ultralight or Ultralight C
        uid->subtype     = PN5180_MIFARE_ULTRALIGHT;
        *blocks_count    = 16;
        *block_size      = 4;
        need_reselection = pn5180_14443_detect_ultralight_variant(pn5180, &uid->subtype, blocks_count);
        break;
    case 0x08:
        ESP_LOGD(TAG, "Detected MIFARE Classic 1K");
        uid->subtype  = PN5180_MIFARE_CLASSIC_1K;
        *blocks_count = 64; // 16 sectors * 4 blocks
        *block_size   = 16;
        break;
    case 0x09: // MIFARE Mini
        ESP_LOGD(TAG, "Detected MIFARE Classic Mini");
        uid->subtype  = PN5180_MIFARE_CLASSIC_MINI;
        *blocks_count = 20; // 5 sectors * 4 blocks
        *block_size   = 16;
        break;
    case 0x10: // MIFARE Plus S (2K)
    case 0x11: // MIFARE Plus X (2K)
        ESP_LOGD(TAG, "Detected MIFARE Plus 2K");
        uid->subtype  = PN5180_MIFARE_PLUS_2K;
        *blocks_count = 128; // 32 sectors * 4 blocks
        *block_size   = 16;
        break;
    case 0x18:
        ESP_LOGD(TAG, "Detected MIFARE Classic 4K");
        uid->subtype  = PN5180_MIFARE_CLASSIC_4K;
        *blocks_count = 256; // 32 sectors * 4 blocks + 8 sectors * 16 blocks
        *block_size   = 16;
        break;
    case 0x20: // ISO 14443-4 (DESFire family)
    case 0x24: // DESFire EV1/EV2/EV3
        ESP_LOGD(TAG, "Detected MIFARE DESFire (ISO 14443-4)");
        uid->subtype  = PN5180_MIFARE_DESFIRE;
        *block_size   = 1;
        *blocks_count = 0;
        pn5180_14443_detect_desfire_capacity(pn5180, blocks_count);
        break;
    case 0x28:
        ESP_LOGD(TAG, "Detected MIFARE Plus 4K");
        uid->subtype  = PN5180_MIFARE_CLASSIC_1K; // Emulated 1K
        *blocks_count = 64;
        *block_size   = 16;
        break;
    case 0x38:
        ESP_LOGD(TAG, "Detected MIFARE Plus 4K");
        uid->subtype  = PN5180_MIFARE_CLASSIC_4K; // Emulated 4K
        *blocks_count = 256;
        *block_size   = 16;
        break;
    default:
        ESP_LOGD(TAG, "Unknown or unsupported MIFARE type (SAK: 0x%02X), defaulting to Classic 1K", uid->sak);
        uid->subtype  = PN5180_MIFARE_CLASSIC_1K;
        *blocks_count = 64;
        *block_size   = 16;
        break;
    }
    return need_reselection;
}

static bool pn5180_14443_select_by_uid( //
    pn5180_t  *pn5180,                  //
    nfc_uid_t *uid                      //
)
{
    uint8_t current_level = 1;
    uint8_t uid_offset    = 0;
    uint8_t sak           = 0;
    uint8_t level_data[5]; // 4 data bytes + 1 BCC
    uint8_t atqa[2];
    prepare_14443A_activation(pn5180);
    if (!pn5180_14443_sendWUPA(pn5180, atqa)) {
        ESP_LOGE(TAG, "No card in field for direct selection");
        pn5180_clearAllIRQs(pn5180);
        return false;
    }

    while (current_level <= 3) {
        // Validate we have enough UID bytes remaining
        if (uid_offset >= uid->uid_length) {
            ESP_LOGE(TAG, "UID offset %d exceeds UID length %d at level %d", uid_offset, uid->uid_length,
                     current_level);
            pn5180_clearAllIRQs(pn5180);
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
                pn5180_clearAllIRQs(pn5180);
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
            pn5180_clearAllIRQs(pn5180);
            return false;
        }

        // 3. Check if UID is complete
        if (!(sak & 0x04)) {
            ESP_LOGI(TAG, "Card successfully selected via direct path!");
            // Determine card type and capacity from SAK
            if (uid->sak != sak) {
                uid->sak = sak;
            }
            return true;
        }
        current_level++;
    }
    return false;
}

static bool pn5180_14443_mifareBlockRead(pn5180_t *pn5180, int blockno, uint8_t *buffer, size_t buffer_len)
{
    // Do not toggle CRC here; it must remain as set by SELECT/AUTH

    uint8_t cmd_buf[2];
    cmd_buf[0] = 0x30; // MIFARE Read command
    cmd_buf[1] = (uint8_t)blockno;

    ESP_LOGD(TAG, "Sending MIFARE Read: cmd=0x%02X block=%d", cmd_buf[0], blockno);
    ESP_LOGD(TAG, "READ data: 0x%02X 0x%02X", cmd_buf[0], cmd_buf[1]);

    // Clear IRQs before sending
    pn5180_clearAllIRQs(pn5180);

    // Send read command - Crypto1 state will be preserved by pn5180_sendData if active
    if (!pn5180_sendData(pn5180, cmd_buf, 2, 0x00)) {
        ESP_LOGE(TAG, "Failed to send MIFARE Read command for block %d", blockno);
        return false;
    }

    uint32_t irqStatus;
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "MIFARE Read", &irqStatus)) {
        ESP_LOGE(TAG, "Timeout waiting for MIFARE block %d read response", blockno);
        return false;
    }

    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        ESP_LOGE(TAG, "Error during MIFARE block %d read", blockno);
        return false;
    }

    // Check RX_STATUS for protocol/integrity errors
    uint32_t rxStatus;
    if (!pn5180_readRegister(pn5180, RX_STATUS, &rxStatus)) {
        ESP_LOGE(TAG, "Failed to read RX_STATUS for block %d", blockno);
        return false;
    }

    if (rxStatus & (RX_PROTOCOL_ERROR | RX_DATA_INTEGRITY_ERROR)) {
        ESP_LOGE(TAG, "RX error during MIFARE block %d read (RX_STATUS=0x%08lX)", blockno, rxStatus);
        pn5180_clearAllIRQs(pn5180);
        return false;
    }

    uint16_t rxLen = rxStatus & RX_BYTES_RECEIVED_MASK;
    if (rxLen != 16 && rxLen != 4) {
        ESP_LOGE(TAG,
                 "MIFARE block %d read returned incorrect length: %d (expected 16 for Classic or 4 for Ultralight)",
                 blockno, rxLen);
        pn5180_clearAllIRQs(pn5180);
        return false;
    } else {
        ESP_LOGD(TAG, "MIFARE block %d read returned %d bytes", blockno, rxLen);
    }

    // Always read data from PN5180 to clear its internal buffer
    // Use temporary buffer if user buffer is too small
    uint8_t temp_buffer[16];
    uint8_t *read_buffer = (rxLen <= buffer_len) ? buffer : temp_buffer;
    
    if (!pn5180_readData(pn5180, rxLen, read_buffer)) {
        ESP_LOGE(TAG, "Failed to read MIFARE block %d data", blockno);
        pn5180_clearAllIRQs(pn5180);
        return false;
    }

    if (rxLen > buffer_len) {
        ESP_LOGD(TAG, "MIFARE block %d read returned %d bytes, but buffer is only %zu bytes, return required length", blockno, rxLen, buffer_len);
        memcpy(buffer, temp_buffer, buffer_len);
    }

    pn5180_clearAllIRQs(pn5180);
    return true;
}

static int pn5180_14443_mifareBlockWrite(pn5180_t *pn5180, int blockno, const uint8_t *buffer)
{
    // Do not toggle CRC here; it must remain as set by SELECT/AUTH
    uint8_t cmd_buf[2];
    cmd_buf[0] = 0xA0; // MIFARE Write command
    cmd_buf[1] = (uint8_t)blockno;
    ESP_LOGD(TAG, "Sending MIFARE Write command: 0x%02X 0x%02X", cmd_buf[0], cmd_buf[1]);
    if (!pn5180_sendData(pn5180, cmd_buf, 2, 0x00)) {
        ESP_LOGE(TAG, "Failed to send MIFARE Write command for block %d", blockno);
        return -1;
    }

    uint32_t irqStatus;
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "MIFARE Write ACK", &irqStatus)) {
        ESP_LOGE(TAG, "Timeout waiting for MIFARE block %d write ACK", blockno);
        return -1;
    }

    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        ESP_LOGE(TAG, "Error during MIFARE block %d write ACK", blockno);
        pn5180_clearAllIRQs(pn5180);
        return -1;
    }

    uint16_t rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen != 1) {
        ESP_LOGE(TAG, "MIFARE block %d write ACK returned incorrect length: %d", blockno, rxLen);
        pn5180_clearAllIRQs(pn5180);
        return -2;
    }

    uint8_t ack;
    if (!pn5180_readData(pn5180, 1, &ack)) {
        ESP_LOGE(TAG, "Failed to read MIFARE block %d write ACK", blockno);
        pn5180_clearAllIRQs(pn5180);
        return -2;
    }

    pn5180_clearAllIRQs(pn5180);

    if ((ack & 0x0F) != 0x0A) {
        ESP_LOGE(TAG, "MIFARE block %d write NACK received: 0x%02X", blockno, ack);
        return -3;
    }

    // Send 16 bytes of data to write
    ESP_LOGD(TAG, "Sending 16 bytes of write data for block %d", blockno);
    if (!pn5180_sendData(pn5180, buffer, 16, 0x00)) {
        ESP_LOGE(TAG, "Failed to send MIFARE block %d data for writing", blockno);
        return -4;
    }

    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "MIFARE Write Final ACK", &irqStatus)) {
        ESP_LOGE(TAG, "Timeout waiting for MIFARE block %d write final ACK", blockno);
        return -5;
    }

    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        ESP_LOGE(TAG, "Error during MIFARE block %d write final ACK", blockno);
        pn5180_clearAllIRQs(pn5180);
        return -5;
    }

    rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen != 1) {
        ESP_LOGE(TAG, "MIFARE block %d write final ACK returned incorrect length: %d", blockno, rxLen);
        pn5180_clearAllIRQs(pn5180);
        return -6;
    }

    if (!pn5180_readData(pn5180, 1, &ack)) {
        ESP_LOGE(TAG, "Failed to read MIFARE block %d write final ACK", blockno);
        pn5180_clearAllIRQs(pn5180);
        return -7;
    }

    pn5180_clearAllIRQs(pn5180);

    if ((ack & 0x0F) != 0x0A) {
        ESP_LOGE(TAG, "MIFARE block %d write final NACK received: 0x%02X", blockno, ack);
        return -8;
    }
    return 0;
}
