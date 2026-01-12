#pragma once

#include "driver/gpio.h"
#include "driver/spi_master.h"

#define MIFARE_CLASSIC_KEYA 0x60 // Mifare Classic key A
#define MIFARE_CLASSIC_KEYB 0x61 // Mifare Classic key B

// PN5180 IRQ_STATUS
#define RX_IRQ_STAT              (1 << 0)  // End of RF receiption IRQ
#define TX_IRQ_STAT              (1 << 1)  // End of RF transmission IRQ
#define IDLE_IRQ_STAT            (1 << 2)  // IDLE IRQ
#define CARD_ACTIVATED_IRQ_STAT  (1 << 4)  // Card activated IRQ
#define RFOFF_DET_IRQ_STAT       (1 << 6)  // RF Field OFF detection IRQ
#define RFON_DET_IRQ_STAT        (1 << 7)  // RF Field ON detection IRQ
#define TX_RFOFF_IRQ_STAT        (1 << 8)  // RF Field OFF in PCD IRQ
#define TX_RFON_IRQ_STAT         (1 << 9)  // RF Field ON in PCD IRQ
#define RF_ACTIVE_ERROR_IRQ_STAT (1 << 10) // RF Active error IRQ
#define RX_SOF_DET_IRQ_STAT      (1 << 14) // RF SOF Detection IRQ
#define RX_SC_DET_IRQ_STAT       (1 << 15) // RF SCD Detection IRQ
#define GENERAL_ERROR_IRQ_STAT   (1 << 17) // General error IRQ
#define LPCD_IRQ_STAT            (1 << 19) // LPCD Detection IRQ

// PN5180 RX_STATUS
#define RX_COLL_POS_START            19 // Bits [25:19] - bit position of the first detected collision in a received frame
#define RX_COLL_POS_MASK             0x7F
#define RX_COLLISION_DETECTED        (1 << 18) // Bit 18 - Collision detected flag
#define RX_PROTOCOL_ERROR            (1 << 17) // Bit 17 - Protocol error flag
#define RX_DATA_INTEGRITY_ERROR      (1 << 16) // Bit 16 - Data integrity error flag
#define RX_NUM_LAST_BITS_START       13        // Bits [15:13] - Number of valid bits in the last received byte
#define RX_NUM_LAST_BITS_MASK        0x07
#define RX_NUM_FRAMES_RECEIVED_START 9 // Bits [12:9] - Number of frames received
#define RX_NUM_FRAMES_RECEIVED_MASK  0x0F
#define RX_BYTES_RECEIVED_START      0 // Bits [8:0] - Number of bytes received
#define RX_BYTES_RECEIVED_MASK       0x1FF

// PN5180 EEPROM Addresses
#define DIE_IDENTIFIER   (0x00)
#define PRODUCT_VERSION  (0x10)
#define FIRMWARE_VERSION (0x12)
#define EEPROM_VERSION   (0x14)
#define IRQ_PIN_CONFIG   (0x1A)

// PN5180 EEPROM Addresses - LPCD (Low Power Card Detection)
#define DPC_XI (0x5C) // DPC AGC Trim Value

// PN5180 Registers
#define SYSTEM_CONFIG      (0x00)
#define IRQ_ENABLE         (0x01)
#define IRQ_STATUS         (0x02)
#define IRQ_CLEAR          (0x03)
#define TRANSCEIVE_CONTROL (0x04)

// SYSTEM_CONFIG register bit masks
#define SYSTEM_CONFIG_MFC_CRYPTO_ON          (1 << 6)   // Bit 6 - MIFARE Crypto1 enabled
#define SYSTEM_CONFIG_TX_MODE_MASK           0x00000003 // Bits 0-2 - Transceiver mode
#define SYSTEM_CONFIG_TX_MODE_IDLE           0x00000000
#define SYSTEM_CONFIG_TX_MODE_TRANSCEIVE     0x00000003
#define SYSTEM_CONFIG_CLEAR_CRYPTO_MASK      0xFFFFFFBF // ~(1<<6) - Clear MFC_CRYPTO_ON bit
#define SYSTEM_CONFIG_CLEAR_TX_MODE_MASK     0xFFFFFFF8 // ~0x07 - Clear transceiver state bits
#define TIMER1_RELOAD      (0x0c)
#define TIMER1_CONFIG      (0x0f)
#define RX_WAIT_CONFIG     (0x11)
#define CRC_RX_CONFIG      (0x12)
#define RX_STATUS          (0x13)
#define TX_WAIT_CONFIG     (0x17)
#define TX_CONFIG          (0x18)
#define CRC_TX_CONFIG      (0x19)
#define RF_STATUS          (0x1d)
#define SYSTEM_STATUS      (0x24)
#define TEMP_CONTROL       (0x25)
#define AGC_REF_CONFIG     (0x26)

typedef struct _pn5180_spi_t
{
    gpio_num_t          sck;
    gpio_num_t          miso;
    gpio_num_t          mosi;
    int                 clock_speed_hz;
    spi_device_handle_t spi_handle;
    spi_host_device_t   host_id;
} pn5180_spi_t;

#define PN5180_MAX_BUF_SIZE 512 // Maximum buffer size for PN5180 commands

typedef struct _pn5180_t
{
    uint8_t      *send_buf;
    uint8_t      *recv_buf;
    int64_t       timeout_ms;
    pn5180_spi_t *spi;
    gpio_num_t    nss;
    gpio_num_t    busy;
    gpio_num_t    rst;
    uint8_t       tx_config;
    uint8_t       rx_config;
    bool          is_rf_on;
} pn5180_t;

typedef enum _pn5180_mifare_subtype_t
{
    PN5180_MIFARE_UNKNOWN = 0,
    PN5180_MIFARE_CLASSIC_1K,
    PN5180_MIFARE_CLASSIC_MINI,
    PN5180_MIFARE_CLASSIC_4K,
    PN5180_MIFARE_ULTRALIGHT,
    PN5180_MIFARE_ULTRALIGHT_C,
    PN5180_MIFARE_ULTRALIGHT_EV1,
    PN5180_MIFARE_NTAG213,
    PN5180_MIFARE_NTAG215,
    PN5180_MIFARE_NTAG216,
    PN5180_MIFARE_PLUS_2K,
    PN5180_MIFARE_PLUS_4K,
    PN5180_MIFARE_DESFIRE,
} __attribute__((__packed__)) mifare_type_t;

typedef struct
{
    int8_t        uid_length;
    uint8_t       sak;
    mifare_type_t subtype;
    uint8_t       uid[10];
} nfc_uid_t;

typedef struct
{
    int       uids_count;
    nfc_uid_t uids[1];
} nfc_uids_array_t;

struct _pn5180_proto_t;

typedef nfc_uids_array_t *funct_get_all_uids_t(struct _pn5180_proto_t *pn5180_proto);

typedef bool func_setup_rf_t(struct _pn5180_proto_t *pn5180_proto);
typedef bool func_select_by_uid_t(        //
    struct _pn5180_proto_t *pn5180_proto, //
    nfc_uid_t              *uid           //
);

typedef bool func_authenticate_t(         //
    struct _pn5180_proto_t *pn5180_proto, //
    const uint8_t          *key,          //
    uint8_t                 keyType,      //
    const nfc_uid_t        *uid,          //
    int                     blockno       //
);
/*
    Returns true if card has to be reselected after detection
*/
typedef bool funct_detect_card_type_t( //
    pn5180_t  *pn5180,                 //
    nfc_uid_t *uid,                    //
    int       *blocks_count,           //
    int       *block_size              //
);

typedef bool func_block_read_t(struct _pn5180_proto_t *pn5180_proto, int blockno, uint8_t *buffer, size_t buffer_len);
typedef int  func_block_write_t(struct _pn5180_proto_t *pn5180_proto, int blockno, const uint8_t *buffer);
typedef bool func_halt_t(struct _pn5180_proto_t *pn5180_proto);

typedef struct _pn5180_proto_t
{
    pn5180_t                 *pn5180;
    func_setup_rf_t          *setup_rf;
    funct_get_all_uids_t     *get_all_uids;
    func_select_by_uid_t     *select_by_uid;
    func_block_read_t        *block_read;
    func_block_write_t       *block_write;
    func_authenticate_t      *authenticate;
    funct_detect_card_type_t *detect_card_type_and_capacity;
    func_halt_t              *halt;
} pn5180_proto_t;

typedef enum
{
    PN5180_TS_Idle         = 0,
    PN5180_TS_WaitTransmit = 1,
    PN5180_TS_Transmitting = 2,
    PN5180_TS_WaitReceive  = 3,
    PN5180_TS_WaitForData  = 4,
    PN5180_TS_Receiving    = 5,
    PN5180_TS_LoopBack     = 6,
    PN5180_TS_RESERVED     = 7
} pn5180_transceive_state_t;

pn5180_spi_t *pn5180_spi_init(spi_host_device_t host_id, gpio_num_t sck, gpio_num_t miso, gpio_num_t mosi,
                              int clock_speed_hz);
pn5180_t     *pn5180_init(pn5180_spi_t *spi, gpio_num_t nss, gpio_num_t busy, gpio_num_t rst);
void          pn5180_deinit(pn5180_t *pn5180, bool free_spi_bus);

bool pn5180_writeRegister(pn5180_t *pn5180, uint8_t reg, uint32_t value);
bool pn5180_writeRegisterWithOrMask(pn5180_t *pn5180, uint8_t addr, uint32_t mask);
bool pn5180_writeRegisterWithAndMask(pn5180_t *pn5180, uint8_t addr, uint32_t mask);
bool pn5180_readRegister(pn5180_t *pn5180, uint8_t reg, uint32_t *value);
bool pn5180_readEEprom(pn5180_t *pn5180, uint8_t addr, uint8_t *buffer, int len);
bool pn5180_writeEEprom(pn5180_t *pn5180, uint8_t addr, uint8_t *buffer, int len);

bool    pn5180_sendData(pn5180_t *pn5180, const uint8_t *data, int len, uint8_t validBits);
bool    pn5180_readData(pn5180_t *pn5180, int len, uint8_t *buffer);
bool    pn5180_prepareLPCD(pn5180_t *pn5180);
bool    pn5180_switchToLPCD(pn5180_t *pn5180, uint16_t wakeupCounterInMs);
int16_t pn5180_mifareAuthenticate(pn5180_t *pn5180, uint8_t blockno, const uint8_t *key, uint8_t keyType,
                                  const uint8_t uid[4]);
bool    pn5180_loadRFConfig(pn5180_t *pn5180, uint8_t txConf, uint8_t rxConf);
bool    pn5180_setRF_on(pn5180_t *pn5180);
bool    pn5180_setRF_off(pn5180_t *pn5180);
bool    pn5180_sendCommand(pn5180_t *pn5180, uint8_t *sendBuffer, size_t sendBufferLen, uint8_t *recvBuffer,
                           size_t recvBufferLen);
// Helper to clear all IRQ flags
uint32_t pn5180_rxBytesReceived(pn5180_t *pn5180);
bool     pn5180_reset(pn5180_t *pn5180);
uint32_t pn5180_getIRQStatus(pn5180_t *pn5180);
bool     pn5180_clearIRQStatus(pn5180_t *pn5180, uint32_t irqMask);

pn5180_transceive_state_t pn5180_getTransceiveState(pn5180_t *pn5180);

void pn5180_delay_ms(int ms);
bool pn5180_wait_for_irq(pn5180_t *pn5180, uint32_t irq_mask, const char *operation, uint32_t *irqStatus);
bool pn5180_begin_transceive(pn5180_t *pn5180);

static void inline pn5180_enable_rx_crc(pn5180_t *pn5180)
{
    pn5180_writeRegisterWithOrMask(pn5180, CRC_RX_CONFIG, 0x01);
}

static void inline pn5180_enable_tx_crc(pn5180_t *pn5180)
{
    pn5180_writeRegisterWithOrMask(pn5180, CRC_TX_CONFIG, 0x01);
}

static void inline pn5180_enable_crc(pn5180_t *pn5180)
{
    pn5180_enable_rx_crc(pn5180);
    pn5180_enable_tx_crc(pn5180);
}

static void inline pn5180_disable_rx_crc(pn5180_t *pn5180)
{
    pn5180_writeRegisterWithAndMask(pn5180, CRC_RX_CONFIG, 0xFFFFFFFE);
}

static void inline pn5180_disable_tx_crc(pn5180_t *pn5180)
{
    pn5180_writeRegisterWithAndMask(pn5180, CRC_TX_CONFIG, 0xFFFFFFFE);
}

static void inline pn5180_disable_crc(pn5180_t *pn5180)
{
    pn5180_disable_rx_crc(pn5180);
    pn5180_disable_tx_crc(pn5180);
}

static bool inline pn5180_clearAllIRQs(pn5180_t *pn5180)
{
    return pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
}

static bool inline pn5180_set_transceiver_idle(pn5180_t *pn5180)
{
    bool ret = pn5180_writeRegisterWithAndMask(pn5180, SYSTEM_CONFIG, 0xFFFFFFF8); // Idle/StopCom Command
    if (ret) {
        pn5180_clearAllIRQs(pn5180);
    }
    return ret;
}
