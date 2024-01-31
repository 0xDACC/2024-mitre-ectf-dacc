/**
 * @file packets.h
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief I2C Packets as outlined in design document
 * @version 0.1
 * @date 2024-01-30
 *
 * @copyright Copyright (c) 2024
 *
 */

#ifndef PACKETS
#define PACKETS
#ifndef __PACKETS__
#define __PACKETS__

#include <stdint.h>

/**
 * @brief Common packet header
 *
 */
typedef struct {
    uint32_t magic : 8;
    uint32_t checksum : 24;
} header_t;

/**
 * @brief Boot command packet payload
 *
 */
typedef struct {
    uint8_t len;
    uint8_t data[4];
    uint8_t sig[65];
} boot_payload_t;

/**
 * @brief Boot ACK packet payload
 *
 */
typedef struct {
    uint8_t len;
    uint8_t data[1];
    uint8_t sig[65];
} boot_ack_payload_t;

/**
 * @brief Secure packet payload
 *
 */
typedef struct {
    uint64_t magic : 8;
    uint64_t len : 8;
    uint64_t nonce : 48;
    uint8_t data[255];
    uint8_t hmac[32];
} secure_payload_t;

/**
 * @brief Key exchange packet payload
 *
 */
typedef struct {
    uint8_t len;
    uint8_t material[32];
    uint8_t hash[32];
} kex_payload_t;

/**
 * @brief Full boot command packet
 *
 */
typedef struct {
    header_t header;
    boot_payload_t payload;
} boot_packet_t;

/**
 * @brief Full boot ACK packet
 *
 */
typedef struct {
    header_t header;
    boot_ack_payload_t payload;
} boot_ack_packet_t;

/**
 * @brief Full secure packet
 *
 */
typedef struct {
    header_t header;
    secure_payload_t payload;
} secure_packet_t;

/**
 * @brief Full key exchange packet
 *
 */
typedef struct {
    header_t header;
    kex_payload_t payload;
} kex_packet_t;
#endif

#endif /* PACKETS */
