/**
 * @file component.cpp
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief Main component file
 * @version 0.1
 * @date 2024-02-22
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "board.h"
#include "flc.h"
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "crc32.h"
#include "errors.h"
#include "packets.h"
#include "random.h"
#include "simple_i2c_peripheral.h"

#include "tinycrypt/ctr_mode.h"
#include "tinycrypt/ecc.h"
#include "tinycrypt/ecc_dh.h"
#include "tinycrypt/ecc_dsa.h"
#include "tinycrypt/hmac.h"
#include "tinycrypt/sha256.h"

// Includes from containerized build
#include "ectf_params_secure.h"
#include "global_secrets_secure.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

// Core function definitions
static error_t component_process_cmd(const uint8_t *const data);
static error_t process_attest(const uint8_t *const data);
static error_t process_boot(const uint8_t *const data);
static error_t process_kex(const uint8_t *const data);
static error_t process_list(const uint8_t *const data);
static error_t process_replace(const uint8_t *const data);
static error_t process_validate(const uint8_t *const data);

enum class state_t { PREBOOT, POSTBOST };
volatile state_t state = state_t::PREBOOT;

uint8_t shared_secret[32] = {};
uint8_t private_key[32] = {};
uint8_t public_key[64] = {};
uint32_t nonce = {};
uint8_t ctr[16] = {};
using namespace i2c;

/**
 * @brief Secure Send
 *
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent
 *
 * Securely send data over I2C. This function is utilized in POST_BOOT
 * functionality. This function must be implemented by your team to align with
 * the security requirements.
 */
static void secure_send(const uint8_t *const buffer, const uint8_t len) {
    uint8_t payload[sizeof(payload_t<packet_type_t::SECURE>)] = {};
    uint8_t hash[32] = {};
    tc_aes_key_sched_struct aes_key = {};
    tc_hmac_state_struct hmac_ctx = {};
    tc_sha256_state_struct sha256_ctx = {};

    uint8_t hmac[32] = {};

    packet_t<packet_type_t::SECURE> tx_packet = {};
    tx_packet.header.magic = packet_magic_t::ENCRYPTED;

    payload[0] = static_cast<uint8_t>(packet_magic_t::DECRYPTED);
    payload[1] = len;
    memcpy(&payload[2], &nonce, 0x04);
    memcpy(&payload[6], buffer, len);
    tc_hmac_init(&hmac_ctx);
    tc_hmac_set_key(&hmac_ctx, HMAC_KEY, 32);
    tc_hmac_update(&hmac_ctx, &payload[0], 262);
    tc_hmac_final(hmac, 32, &hmac_ctx);
    memcpy(&payload[262], hmac, 32);

    tc_sha256_init(&sha256_ctx);
    tc_sha256_update(&sha256_ctx, shared_secret, 32);
    tc_sha256_final(hash, &sha256_ctx);

    if (ctr[2] != 0xDA && ctr[3] != 0xCC) {
        memcpy(ctr, "\x00X\xDA\xCC\x00X\xDA\xCC", 8);
        memcpy(&ctr[8], &hash[16], 0x8);
    }
    tc_aes128_set_encrypt_key(&aes_key, hash);
    tc_ctr_mode(reinterpret_cast<uint8_t *>(&tx_packet.payload),
                sizeof(tx_packet.payload), payload, sizeof(payload), ctr,
                &aes_key);

    tx_packet.header.checksum =
        calc_checksum(&tx_packet.payload, sizeof(tx_packet.payload));

    send_packet<packet_type_t::SECURE>(tx_packet);
}

/**
 * @brief Secure Receive
 *
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 *
 * @return int: number of bytes received, negative if error
 *
 * Securely receive data over I2C. This function is utilized in POST_BOOT
 * functionality. This function must be implemented by your team to align
 * with the security requirements.
 */
static int secure_receive(uint8_t *const buffer) {
    uint8_t payload[sizeof(payload_t<packet_type_t::SECURE>)] = {};
    uint8_t hash[32] = {};
    tc_aes_key_sched_struct aes_key = {};
    tc_hmac_state_struct hmac_ctx = {};
    tc_sha256_state_struct sha256_ctx = {};

    uint8_t hmac[32] = {};

    // Wait for packet
    while (static_cast<packet_magic_t>(rxbuf[0]) != packet_magic_t::ENCRYPTED) {
        continue;
    }

    packet_t<packet_type_t::SECURE> rx_packet = {};
    rx_packet.header.magic = static_cast<packet_magic_t>(rxbuf[0]);

    memcpy(&rx_packet.header.checksum, const_cast<uint8_t *>(&rxbuf[1]), 0x04);
    memcpy(&rx_packet.payload, const_cast<uint8_t *>(&rxbuf[5]),
           sizeof(rx_packet.payload));

    const uint32_t expected_checksum =
        calc_checksum(&rx_packet.payload, sizeof(rx_packet.payload));

    if (rx_packet.header.magic != packet_magic_t::ENCRYPTED) {
        // Invalid magic
        return -1;
    } else if (rx_packet.header.checksum != expected_checksum) {
        // Checksum failed
        return -1;
    }

    tc_sha256_init(&sha256_ctx);
    tc_sha256_update(&sha256_ctx, shared_secret, 32);
    tc_sha256_final(hash, &sha256_ctx);

    if (ctr[2] != 0xDA && ctr[3] != 0xCC) {
        memcpy(ctr, "\x00X\xDA\xCC\x00X\xDA\xCC", 8);
        memcpy(&ctr[8], &hash[16], 0x8);
    }

    tc_aes128_set_encrypt_key(&aes_key, hash);
    tc_ctr_mode(payload, sizeof(payload),
                reinterpret_cast<uint8_t *>(&rx_packet.payload),
                sizeof(rx_packet.payload), ctr, &aes_key);

    tc_hmac_init(&hmac_ctx);
    tc_hmac_set_key(&hmac_ctx, HMAC_KEY, 32);
    tc_hmac_update(&hmac_ctx, &payload[0], 262);
    tc_hmac_final(hmac, 32, &hmac_ctx);

    if (payload[0] != static_cast<uint8_t>(packet_magic_t::DECRYPTED)) {
        // Invalid payload
        return -1;
    } else if (memcmp(&payload[2], &nonce, 0x04) != 0) {
        // Invalid nonce
        return -1;
    } else if (memcmp(hmac, &payload[262], 32) != 0) {
        // HMAC failed
        return -1;
    }
    memcpy(buffer, &payload[6], payload[1]);
    packet_t<packet_type_t::SECURE> tx_packet = {};
    tx_packet.header.magic = packet_magic_t::ENCRYPTED;

    payload[0] = static_cast<uint8_t>(packet_magic_t::DECRYPTED);
    payload[1] = 0;
    memcpy(&payload[2], &nonce, 0x04);

    tc_hmac_init(&hmac_ctx);
    tc_hmac_set_key(&hmac_ctx, HMAC_KEY, 32);
    tc_hmac_update(&hmac_ctx, &payload[0], 262);
    tc_hmac_final(hmac, 32, &hmac_ctx);
    memcpy(&payload[262], hmac, 32);

    tc_sha256_init(&sha256_ctx);
    tc_sha256_update(&sha256_ctx, shared_secret, 32);
    tc_sha256_final(hash, &sha256_ctx);

    if (ctr[2] != 0xDA && ctr[3] != 0xCC) {
        memcpy(ctr, "\x00X\xDA\xCC\x00X\xDA\xCC", 8);
        memcpy(&ctr[8], &hash[16], 0x8);
    }

    tc_aes128_set_encrypt_key(&aes_key, hash);
    tc_ctr_mode(reinterpret_cast<uint8_t *>(&tx_packet.payload),
                sizeof(tx_packet.payload), payload, sizeof(payload), ctr,
                &aes_key);

    tx_packet.header.checksum =
        calc_checksum(&tx_packet.payload, sizeof(tx_packet.payload));

    send_packet<packet_type_t::SECURE>(tx_packet);
    return payload[1];
}

// Example boot sequence
// Your design does not need to change this
static void boot() {

// POST BOOT FUNCTIONALITY
// DO NOT REMOVE IN YOUR DESIGN
#ifdef POST_BOOT
    POST_BOOT
#else
    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
    // LED loop to show that boot occurred
    while (true) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
#endif
}

// Handle a transaction from the AP
static error_t component_process_cmd(const uint8_t *const data) {
    printf("Processing command\n");
    if (data == nullptr) {
        printf("Error: Null data received\n");
        return error_t::ERROR;
    }
    printf("Processing command %d\n", +data[0]);
    switch (static_cast<packet_magic_t>(data[0])) {
    case packet_magic_t::ATTEST:
        printf("Processing attest\n");
        return process_attest(data);
        break;
    case packet_magic_t::BOOT:
        return process_boot(data);
        break;
    case packet_magic_t::REPLACE:
        return process_replace(data);
        break;
    case packet_magic_t::KEX:
        return process_kex(data);
        break;
    case packet_magic_t::LIST:
        printf("Processing list\n");
        return process_list(data);
        break;
    case packet_magic_t::ENCRYPTED:
        return state == state_t::POSTBOST ? error_t::SUCCESS : error_t::ERROR;
        break;
    default:
        printf("Error: Unrecognized command received %d\n", data[0]);
        return error_t::ERROR;
    }
}

static error_t process_boot(const uint8_t *const data) {
    packet_t<packet_type_t::BOOT_COMMAND> rx_packet;
    rx_packet.header.magic = packet_magic_t::LIST;

    memcpy(&rx_packet.header.checksum, &data[1], 0x04);
    memcpy(&rx_packet.payload, &data[5], sizeof(rx_packet.payload));

    const uint32_t expected_checksum =
        calc_checksum(&rx_packet.payload, sizeof(rx_packet.payload));
    if (rx_packet.header.checksum != expected_checksum) {
        // Checksum failed
        return error_t::ERROR;
    } else if (rx_packet.payload.len != 0x04) {
        // Invalid payload length
        return error_t::ERROR;
    } else if (memcmp(rx_packet.payload.data, "BOOT", 0x4) != 0) {
        // Invalid payload
        return error_t::ERROR;
    } else if (/*sigverify(data) ==*/false) {
        // TODO: Tyler, implement signature verification here
        // Invalid signature
        return error_t::ERROR;
    }

    packet_t<packet_type_t::BOOT_ACK> tx_packet;
    tx_packet.header.magic = packet_magic_t::BOOT_ACK;
    tx_packet.payload.len = 0x40;
    memcpy(tx_packet.payload.data, COMPONENT_BOOT_MSG, 0x40);

    // tx_packet.payload.sig = 0;
    // TODO: Tyler, implement signature algorithm here
    tx_packet.header.checksum =
        calc_checksum(&tx_packet.payload, sizeof(tx_packet.payload));

    send_packet<packet_type_t::BOOT_ACK>(tx_packet);
    state = state_t::POSTBOST;
    return error_t::SUCCESS;
}

static error_t process_list(const uint8_t *const data) {
    printf("Processing list\n");
    packet_t<packet_type_t::LIST_COMMAND> rx_packet = {};
    rx_packet.header.magic = packet_magic_t::LIST;

    memcpy(&rx_packet.header.checksum, &data[1], 0x04);
    memcpy(&rx_packet.payload, &data[5], sizeof(rx_packet.payload));

    const uint32_t expected_checksum =
        calc_checksum(&rx_packet.payload, sizeof(rx_packet.payload));
    if (rx_packet.header.checksum != expected_checksum) {
        // Checksum failed
        return error_t::ERROR;
    } else if (rx_packet.payload.len != 0x00) {
        // Invalid payload length
        return error_t::ERROR;
    }
    packet_t<packet_type_t::LIST_ACK> tx_packet = {};
    tx_packet.header.magic = packet_magic_t::LIST_ACK;
    tx_packet.payload.len = 0x04;

    memcpy(tx_packet.payload.data, &COMPONENT_ID, 0x04);

    tx_packet.header.checksum =
        calc_checksum(&tx_packet.payload, sizeof(tx_packet.payload));

    send_packet<packet_type_t::LIST_ACK>(tx_packet);
    return error_t::SUCCESS;
}

static error_t process_replace(const uint8_t *const data) {
    printf("Processing replace\n");
    packet_t<packet_type_t::REPLACE_COMMAND> rx_packet = {};
    rx_packet.header.magic = packet_magic_t::REPLACE;

    memcpy(&rx_packet.header.checksum, &data[1], 0x04);
    memcpy(&rx_packet.payload, &data[5], sizeof(rx_packet.payload));

    const uint32_t expected_checksum =
        calc_checksum(&rx_packet.payload, sizeof(rx_packet.payload));
    if (rx_packet.header.checksum != expected_checksum) {
        // Checksum failed
        return error_t::ERROR;
    } else if (rx_packet.payload.len != 0x20) {
        // Invalid payload length
        return error_t::ERROR;
    }

    packet_t<packet_type_t::REPLACE_ACK> tx_packet = {};
    tx_packet.header.magic = packet_magic_t::REPLACE_ACK;
    tx_packet.payload.len = 0x41;

    if (uECC_sign(KEYPAIR_C_PRIV, rx_packet.payload.data, 0x20,
                  tx_packet.payload.data, uECC_secp256r1()) != 1) {
        // Couldn't sign
        return error_t::ERROR;
    }

    tx_packet.header.checksum =
        calc_checksum(&tx_packet.payload, sizeof(tx_packet.payload));

    send_packet<packet_type_t::REPLACE_ACK>(tx_packet);
    return error_t::SUCCESS;
}

static error_t process_validate(const uint8_t *const data, const uint32_t len) {
    // This is the signing part (all systems valid on page 5)

    // TODO: Tyler, implement packet checks and signature algorithms
    return error_t::SUCCESS;
}

static error_t process_attest(const uint8_t *const data) {
    packet_t<packet_type_t::ATTEST_COMMAND> rx_packet = {};
    rx_packet.header.magic = packet_magic_t::ATTEST;

    memcpy(&rx_packet.header.checksum, &data[1], 0x04);
    memcpy(&rx_packet.payload, &data[5], sizeof(rx_packet.payload));

    const uint32_t expected_checksum =
        calc_checksum(&rx_packet.payload, sizeof(rx_packet.payload));
    if (rx_packet.header.checksum != expected_checksum) {
        // Checksum failed
        return error_t::ERROR;
    } else if (rx_packet.payload.len != 0x6) {
        // Invalid payload length
        return error_t::ERROR;
    } else if (memcmp(rx_packet.payload.data, "ATTEST", 0x6) != 0) {
        // Invalid payload
        return error_t::ERROR;
    } else if (/*sigverify(data) ==*/false) {
        // TODO: Henry and David, implement signature verification here
        // Invalid signature
        return error_t::ERROR;
    }

    packet_t<packet_type_t::ATTEST_ACK> tx_packet = {};
    tx_packet.header.magic = packet_magic_t::ATTEST_ACK;
    tx_packet.payload.len = 0xC0;

    memcpy(tx_packet.payload.data, ATTEST_LOC_ENC, 0x40);
    memcpy(tx_packet.payload.data + 0x40, ATTEST_DATE_ENC, 0x40);
    memcpy(tx_packet.payload.data + 0x80, ATTEST_CUST_ENC, 0x40);

    // tx_packet.payload.sig = 0;
    // TODO: Henry and David, implement signature algorithm here

    tx_packet.header.checksum =
        calc_checksum(&tx_packet.payload, sizeof(tx_packet.payload));
    printf("Sending Attest ACK\n");
    send_packet<packet_type_t::ATTEST_ACK>(tx_packet);
    return error_t::SUCCESS;
}

static error_t process_kex(const uint8_t *const data) {
    packet_t<packet_type_t::KEX> rx_packet;
    rx_packet.header.magic = static_cast<packet_magic_t>(data[0]);

    memcpy(&rx_packet.header.checksum, &data[1], 0x04);
    memcpy(&rx_packet.payload, &data[5], sizeof(rx_packet.payload));

    const uint32_t expected_checksum =
        calc_checksum(&rx_packet.payload, sizeof(rx_packet.payload));
    tc_sha256_state_struct sha256_ctx = {};

    uint8_t expected_hash[32] = {};
    tc_sha256_init(&sha256_ctx);
    tc_sha256_update(&sha256_ctx, rx_packet.payload.material,
                     sizeof(rx_packet.payload.material));
    tc_sha256_final(expected_hash, &sha256_ctx);

    if (rx_packet.header.checksum != expected_checksum) {
        // Checksum failed
        return error_t::ERROR;
    } else if (rx_packet.payload.len != 0x60) {
        // Invalid payload length
        return error_t::ERROR;
    } else if (uECC_valid_public_key(rx_packet.payload.material,
                                     uECC_secp256r1()) < 0) {
        // Invalid public key
        return error_t::ERROR;
    } else if (memcmp(rx_packet.payload.hash, expected_hash, 0x20) != 0) {
        // Invalid hash
        return error_t::ERROR;
    }

    uECC_make_key(public_key, private_key, uECC_secp256r1());
    uECC_shared_secret(rx_packet.payload.material, private_key, shared_secret,
                       uECC_secp256r1());

    packet_t<packet_type_t::KEX> tx_packet;
    tx_packet.header.magic = packet_magic_t::KEX;
    tx_packet.payload.len = 0x40;
    uECC_compute_public_key(private_key, rx_packet.payload.material,
                            uECC_secp256r1());

    sha256_ctx = {};
    tc_sha256_init(&sha256_ctx);
    tc_sha256_update(&sha256_ctx, tx_packet.payload.material,
                     sizeof(tx_packet.payload.material));
    tc_sha256_final(tx_packet.payload.hash, &sha256_ctx);

    tx_packet.header.checksum =
        calc_checksum(&tx_packet.payload, sizeof(tx_packet.payload));
    send_packet(tx_packet);
    return error_t::SUCCESS;
}

int main() {
    printf("Component Started\n");

    // Enable Global Interrupts
    __enable_irq();

    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    if (i2c_simple_peripheral_init(addr, component_process_cmd) !=
        error_t::SUCCESS) {
        printf("Failed to initialize I2C peripheral.\n");
        return -1;
    }
    if (random_init() != error_t::SUCCESS) {
        printf("Failed to initialize random number generator.\n");
        return -1;
    }

    LED_On(LED2);

    while (true) {
        // Do nothing
        if (state == state_t::POSTBOST) {
            // TODO: Disable all functions
            boot();
        }
    }
}
