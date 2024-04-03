/**
 * @file packets.h
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief I2C Packet formats as outlined in design document
 * @version 0.1
 * @date 2024-01-30
 *
 * @copyright Copyright (c) 2024
 *
 */
#ifndef PACKETS
#define PACKETS

#include <stdint.h>

/**
 * @brief Packet magic values
 *
 */
enum class packet_magic_t : uint8_t {
	ERROR,
	KEX,
	LIST,
	LIST_ACK,
	ATTEST,
	ATTEST_ACK,
	BOOT,
	BOOT_ACK,
	DECRYPTED,
	ENCRYPTED,
};

/**
 * @brief Internal packet types
 *
 */
enum class packet_type_t : uint8_t {
	ERROR,
	KEX,
	LIST_COMMAND,
	LIST_ACK,
	ATTEST_COMMAND,
	ATTEST_ACK,
	BOOT_COMMAND,
	BOOT_ACK,
	SECURE,
};

/**
 * @brief Common packet header
 *
 */
struct header_t {
	packet_magic_t magic;
	uint32_t checksum;
};

template<packet_type_t T> struct __packed payload_t;

/**
 * @brief Error packet payload
 *
 */
template<> struct __packed payload_t<packet_type_t::ERROR> {};

/**
 * @brief Key exchange packet payload
 *
 */
template<> struct __packed payload_t<packet_type_t::KEX> {
	uint8_t len;
	uint8_t material[64];
};

/**
 * @brief List command packet payload
 *
 */
template<> struct __packed payload_t<packet_type_t::LIST_COMMAND> {
	uint8_t len;
};

/**
 * @brief List ack packet payload
 *
 */
template<> struct __packed payload_t<packet_type_t::LIST_ACK> {
	uint8_t len;
	uint8_t data[4];
};

/**
 * @brief Attest packet payload
 *
 */
template<> struct __packed payload_t<packet_type_t::ATTEST_COMMAND> {
	uint8_t len;
	uint8_t data[7];
	uint8_t sig[64];
};

/**
 * @brief Attest ack packet payload
 *
 */
template<> struct __packed payload_t<packet_type_t::ATTEST_ACK> {
	uint8_t len;
	uint8_t data[64];
	uint8_t sig[64];
};

/**
 * @brief Boot command packet payload
 *
 */
template<> struct __packed payload_t<packet_type_t::BOOT_COMMAND> {
	uint8_t len;
	uint8_t data[32];
	uint8_t sig[64];
};

/**
 * @brief Boot command ack packet payload
 * @note The signature is calculated over the AP's data, not the COMP's data
 *
 */
template<> struct __packed payload_t<packet_type_t::BOOT_ACK> {
	uint8_t len;
	uint8_t data[64];
	uint8_t sig[64];
};

/**
 * @brief Secure packet payload
 *
 */
template<> struct __packed payload_t<packet_type_t::SECURE> {
	uint8_t magic;
	uint8_t len;
	uint32_t nonce;
	uint8_t data[64];
	uint8_t __padding[10];	// Pad to multiple of 16 bytes
	uint8_t hmac[32];
};

/**
 * @brief Raw packet data
 *
 * @tparam T Payload type
 */
template<packet_type_t T> struct packet_t {
	header_t header;
	payload_t<T> payload;
};

#endif
