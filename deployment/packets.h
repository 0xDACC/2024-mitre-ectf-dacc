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
	ERROR	   = 0x00,
	KEX		   = 0x01,
	LIST	   = 0x02,
	LIST_ACK   = 0x03,
	ATTEST	   = 0x04,
	BOOT	   = 0x05,
	DECRYPTED  = 0x06,
	ENCRYPTED  = 0x07,
	ATTEST_ACK = 0x08,
	BOOT_ACK   = 0x09
};

/**
 * @brief Internal packet types
 *
 */
enum class packet_type_t : uint8_t {
	ERROR,
	LIST_COMMAND,
	LIST_ACK,
	ATTEST_COMMAND,
	BOOT_COMMAND,
	SECURE,
	KEX,
	ATTEST_ACK,
	BOOT_ACK
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
	uint8_t data[6];
	uint8_t sig[65];
};

/**
 * @brief Boot command packet payload
 *
 */
template<> struct __packed payload_t<packet_type_t::BOOT_COMMAND> {
	uint8_t len;
	uint8_t data[4];
	uint8_t sig[65];
};

/**
 * @brief Secure packet payload
 *
 */
template<> struct __packed payload_t<packet_type_t::SECURE> {
	uint8_t magic;
	uint8_t len;
	uint32_t nonce;
	uint8_t data[256];
	uint8_t hmac[32];
};

/**
 * @brief Key exchange packet payload
 *
 */
template<> struct __packed payload_t<packet_type_t::KEX> {
	uint8_t len;
	uint8_t material[64];
	uint8_t hash[32];
};

/**
 * @brief Attest ack packet payload
 *
 */
template<> struct __packed payload_t<packet_type_t::ATTEST_ACK> {
	uint8_t len;
	uint8_t data[192];
	uint8_t sig[65];
};

/**
 * @brief Boot ack packet payload
 *
 */
template<> struct __packed payload_t<packet_type_t::BOOT_ACK> {
	uint8_t len;
	uint8_t data[64];
	uint8_t sig[65];
};

/**
 * @brief Raw packet data
 *
 * @tparam T Payload type
 */
template<packet_type_t T> struct packet_t {
	const packet_type_t type = T;
	header_t header;
	payload_t<T> payload;
};

#endif