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
#define COMP 1

#include "board.h"
#include "flc.h"
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"

#include <stdio.h>
#include <string.h>

#include "component.h"
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

static volatile bootstate_t boot_state = bootstate_t::PREBOOT;

static uint8_t shared_secret[32] = {};
static uint8_t private_key[32] = {};
static uint8_t public_key[64] = {};
static uint32_t nonce = {};
static uint8_t ctr[16] = {};
using namespace i2c;

void secure_send(const uint8_t *const buffer, const uint8_t len) {
    uint8_t payload[sizeof(payload_t<packet_type_t::SECURE>)] = {};
    uint8_t hash[32] = {};
    tc_aes_key_sched_struct aes_key = {};
    tc_hmac_state_struct hmac_ctx = {};
    tc_sha256_state_struct sha256_ctx = {};

    uint8_t hmac[32] = {};

    // Wait for AP to send request
    while (rxbuf[0] != static_cast<uint8_t>(packet_magic_t::ENCRYPTED)) {
        continue;
    }

    packet_t<packet_type_t::SECURE> rx_packet = {};
    rx_packet.header.magic = static_cast<packet_magic_t>(rxbuf[0]);

    memcpy(&rx_packet.header.checksum, const_cast<uint8_t *>(&rxbuf[1]), 0x04);
    memcpy(&rx_packet.payload, const_cast<uint8_t *>(&rxbuf[5]),
           sizeof(rx_packet.payload));

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
    tc_hmac_update(&hmac_ctx, &payload[0], sizeof(payload) - 32);
    tc_hmac_final(hmac, 32, &hmac_ctx);

    if (payload[0] != static_cast<uint8_t>(packet_magic_t::DECRYPTED)) {
        // Invalid payload
        return;
    } else if (memcmp(&payload[2], &nonce, 0x04) != 0) {
        // Invalid nonce
        return;
    } else if (memcmp(hmac, &payload[sizeof(payload) - 32], 32) != 0) {
        // HMAC failed
        return;
    } else if (payload[6] != 0x0) {
        // Invalid length
        return;
    }

    packet_t<packet_type_t::SECURE> tx_packet = {};
    tx_packet.header.magic = packet_magic_t::ENCRYPTED;

    payload[0] = static_cast<uint8_t>(packet_magic_t::DECRYPTED);
    payload[1] = len;
    memcpy(&payload[2], &nonce, 0x04);
    memcpy(&payload[6], buffer, len);

    tc_hmac_init(&hmac_ctx);
    tc_hmac_set_key(&hmac_ctx, HMAC_KEY, 32);
    tc_hmac_update(&hmac_ctx, &payload[0], sizeof(payload) - 32);
    tc_hmac_final(hmac, 32, &hmac_ctx);
    memcpy(&payload[sizeof(payload) - 32], hmac, 32);

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

    ++nonce;
    send_packet<packet_type_t::SECURE>(tx_packet);
}

int secure_receive(uint8_t *const buffer) {
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
    tc_hmac_update(&hmac_ctx, &payload[0], sizeof(payload) - 32);
    tc_hmac_final(hmac, 32, &hmac_ctx);

    if (payload[0] != static_cast<uint8_t>(packet_magic_t::DECRYPTED)) {
        // Invalid payload
        return -1;
    } else if (memcmp(&payload[2], &nonce, 0x04) != 0) {
        // Invalid nonce
        return -1;
    } else if (memcmp(hmac, &payload[sizeof(payload) - 32], 32) != 0) {
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
    tc_hmac_update(&hmac_ctx, &payload[0], sizeof(payload) - 32);
    tc_hmac_final(hmac, 32, &hmac_ctx);
    memcpy(&payload[sizeof(payload) - 32], hmac, 32);

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

    ++nonce;
    send_packet<packet_type_t::SECURE>(tx_packet);
    return payload[1];
}

static void boot() {

#ifdef POST_BOOT
    POST_BOOT
#else
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
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

error_t component_process_cmd(const uint8_t *const data) {
    if (data == nullptr) {
        return error_t::ERROR;
    }
    if (boot_state == bootstate_t::PREBOOT) {
        switch (static_cast<packet_magic_t>(data[0])) {
        case packet_magic_t::ATTEST:
            return process_attest(data);
            break;
        case packet_magic_t::KEX:
            return process_kex(data);
            break;
        case packet_magic_t::LIST:
            return process_list(data);
            break;
        case packet_magic_t::BOOT:
            return process_boot(data);
            break;
        default:
            return error_t::ERROR;
        }
    } else {
        switch (static_cast<packet_magic_t>(data[0])) {
        case packet_magic_t::ENCRYPTED:
            return error_t::SUCCESS;
            break;
        default:
            return error_t::ERROR;
        }
    }
}

error_t process_boot(const uint8_t *const data) {
    packet_t<packet_type_t::BOOT_COMMAND> rx_packet;
    rx_packet.header.magic = static_cast<packet_magic_t>(data[0]);

    memcpy(&rx_packet.header.checksum, &data[1], 0x04);
    memcpy(&rx_packet.payload, &data[5], sizeof(rx_packet.payload));

    const uint32_t expected_checksum =
        calc_checksum(&rx_packet.payload, sizeof(rx_packet.payload));

    if (rx_packet.header.magic != packet_magic_t::BOOT) {
        // Invalid magic
        return error_t::ERROR;
    } else if (rx_packet.header.checksum != expected_checksum) {
        // Checksum failed
        return error_t::ERROR;
    } else if (rx_packet.payload.len != 0x60) {
        // Invalid payload length
        return error_t::ERROR;
    } else if (uECC_verify(BOOT_A_PUB, rx_packet.payload.data, 0x20,
                           rx_packet.payload.sig, uECC_secp256r1()) != 1) {
        // Invalid signature
        return error_t::ERROR;
    }

    packet_t<packet_type_t::BOOT_ACK> tx_packet;
    tx_packet.header.magic = packet_magic_t::BOOT_ACK;
    tx_packet.payload.len = 0x40;
    memcpy(tx_packet.payload.data, COMPONENT_BOOT_MSG, 0x40);

    if (uECC_sign(BOOT_C_PRIV, rx_packet.payload.data, 0x20,
                  tx_packet.payload.sig, uECC_secp256r1()) != 1) {
        // Couldn't sign
        return error_t::ERROR;
    }
    tx_packet.header.checksum =
        calc_checksum(&tx_packet.payload, sizeof(tx_packet.payload));

    send_packet<packet_type_t::BOOT_ACK>(tx_packet);
    boot_state = bootstate_t::POSTBOST;
    return error_t::SUCCESS;
}

error_t process_list(const uint8_t *const data) {
    packet_t<packet_type_t::LIST_COMMAND> rx_packet = {};
    rx_packet.header.magic = static_cast<packet_magic_t>(data[0]);

    memcpy(&rx_packet.header.checksum, &data[1], 0x04);
    memcpy(&rx_packet.payload, &data[5], sizeof(rx_packet.payload));

    const uint32_t expected_checksum =
        calc_checksum(&rx_packet.payload, sizeof(rx_packet.payload));

    if (rx_packet.header.magic != packet_magic_t::LIST) {
        // Invalid magic
        return error_t::ERROR;
    } else if (rx_packet.header.checksum != expected_checksum) {
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

error_t process_attest(const uint8_t *const data) {
    packet_t<packet_type_t::ATTEST_COMMAND> rx_packet = {};
    rx_packet.header.magic = static_cast<packet_magic_t>(data[0]);

    memcpy(&rx_packet.header.checksum, &data[1], 0x04);
    memcpy(&rx_packet.payload, &data[5], sizeof(rx_packet.payload));

    tc_sha256_state_struct sha256_ctx = {};
    uint8_t hash[32] = {};
    tc_sha256_init(&sha256_ctx);
    tc_sha256_update(&sha256_ctx, rx_packet.payload.data, 0x07);
    tc_sha256_final(hash, &sha256_ctx);

    const uint32_t expected_checksum =
        calc_checksum(&rx_packet.payload, sizeof(rx_packet.payload));
    if (rx_packet.header.magic != packet_magic_t::ATTEST) {
        // Invalid magic
        return error_t::ERROR;
    } else if (rx_packet.header.checksum != expected_checksum) {
        // Checksum failed
        return error_t::ERROR;
    } else if (rx_packet.payload.len != 0x07) {
        // Invalid payload length
        return error_t::ERROR;
    } else if (memcmp(rx_packet.payload.data, "ATTEST", 0x06) != 0) {
        // Invalid payload
        return error_t::ERROR;
    } else if (rx_packet.payload.data[6] > 0x03) {
        // Invalid attest position
        return error_t::ERROR;
    } else if (uECC_verify(ATTEST_A_PUB, hash, 32, rx_packet.payload.sig,
                           uECC_secp256r1()) != 1) {
        // Invalid signature
        return error_t::ERROR;
    }

    packet_t<packet_type_t::ATTEST_ACK> tx_packet = {};
    tx_packet.header.magic = packet_magic_t::ATTEST_ACK;
    tx_packet.payload.len = 0x40;

    if (rx_packet.payload.data[6] == 0x01) {
        memcpy(tx_packet.payload.data, ATTEST_LOC_ENC, 0x40);
    } else if (rx_packet.payload.data[6] == 0x02) {
        memcpy(tx_packet.payload.data, ATTEST_DATE_ENC, 0x40);
    } else if (rx_packet.payload.data[6] == 0x03) {
        memcpy(tx_packet.payload.data, ATTEST_CUST_ENC, 0x40);
    }

    sha256_ctx = {};
    tc_sha256_init(&sha256_ctx);
    tc_sha256_update(&sha256_ctx, tx_packet.payload.data, 64);
    tc_sha256_final(hash, &sha256_ctx);

    if (uECC_sign(ATTEST_C_PRIV, hash, 0x20, tx_packet.payload.sig,
                  uECC_secp256r1()) != 1) {
        // Couldn't sign
        return error_t::ERROR;
    }

    tx_packet.header.checksum =
        calc_checksum(&tx_packet.payload, sizeof(tx_packet.payload));
    send_packet<packet_type_t::ATTEST_ACK>(tx_packet);
    return error_t::SUCCESS;
}

error_t process_kex(const uint8_t *const data) {
    packet_t<packet_type_t::KEX> rx_packet;
    rx_packet.header.magic = static_cast<packet_magic_t>(data[0]);

    memcpy(&rx_packet.header.checksum, &data[1], 0x04);
    memcpy(&rx_packet.payload, &data[5], sizeof(rx_packet.payload));

    const uint32_t expected_checksum =
        calc_checksum(&rx_packet.payload, sizeof(rx_packet.payload));

    if (rx_packet.header.checksum != expected_checksum) {
        // Checksum failed
        return error_t::ERROR;
    } else if (rx_packet.payload.len != 0x40) {
        // Invalid payload length
        return error_t::ERROR;
    } else if (uECC_valid_public_key(rx_packet.payload.material,
                                     uECC_secp256r1()) < 0) {
        // Invalid public key
        return error_t::ERROR;
    }

    uECC_shared_secret(rx_packet.payload.material, private_key, shared_secret,
                       uECC_secp256r1());

    packet_t<packet_type_t::KEX> tx_packet;
    tx_packet.header.magic = packet_magic_t::KEX;
    tx_packet.payload.len = 0x40;
    memcpy(tx_packet.payload.material, public_key, 0x40);

    tx_packet.header.checksum =
        calc_checksum(&tx_packet.payload, sizeof(tx_packet.payload));
    send_packet<packet_type_t::KEX>(tx_packet);
    return error_t::SUCCESS;
}

int main() {
    // Enable Global Interrupts
    __enable_irq();

    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    if (i2c_simple_peripheral_init(addr, component_process_cmd) !=
        error_t::SUCCESS) {
        return -1;
    }
    if (random_init() != error_t::SUCCESS) {
        return -1;
    }

    uECC_make_key(public_key, private_key, uECC_secp256r1());

    LED_On(LED2);

    while (true) {
        if (boot_state == bootstate_t::POSTBOST) {
            boot();
            return 0;
        }
    }
}
