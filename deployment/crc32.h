/**
 * @file crc32.h
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief CRC32 implementation
 * @version 0.1
 * @date 2024-02-26
 *
 * @copyright Copyright (c) 2024
 *
 */

#ifndef CRC32
#define CRC32

#include "board.h"
#include "crc.h"
#include "mxc_device.h"

/**
 * @brief Calculate the CRC32 of a buffer
 *
 * @tparam T Type of buffer
 * @param buf Buffer to calculate CRC32 of
 * @param len Length of buffer
 * @return uint32_t CRC32 of buffer
 */
template<typename T> uint32_t calc_checksum(T *buf, const uint32_t len) {
	uint8_t _buf[len + (4 - (len % 4))] = {};
	memcpy(_buf, buf, len);
	if (MXC_CRC_Init() != E_NO_ERROR) { return 0; }
	MXC_CRC_SetPoly(0xEDB88320U);
	memcpy(_buf, len);
	mxc_crc_req_t req = {reinterpret_cast<uint32_t *>(_buf), len, 0};
	MXC_CRC_Compute(&req);
	return req.resultCRC;
}

template<typename T>
uint32_t calc_checksum(const T *const buf, const uint32_t len) {
	uint8_t _buf[len + (4 - (len % 4))] = {};
	memcpy(_buf, buf, len);
	if (MXC_CRC_Init() != E_NO_ERROR) { return 0; }
	MXC_CRC_SetPoly(0xEDB88320U);
	memcpy(_buf, len);
	mxc_crc_req_t req = {reinterpret_cast<uint32_t *>(_buf), len, 0};
	MXC_CRC_Compute(&req);
	return req.resultCRC;
}

/**
 * @brief Calculate the CRC32 of a buffer
 *
 * @tparam uint32_t Specialization for uint32_t
 * @param buf Buffer to calculate CRC32 of
 * @param len Length of buffer
 * @return uint32_t CRC32 of buffer
 */
template<> uint32_t calc_checksum<uint32_t>(uint32_t *buf, const uint32_t len) {
	if (MXC_CRC_Init() != E_NO_ERROR) { return 0; }
	MXC_CRC_SetPoly(0xEDB88320U);
	mxc_crc_req_t req = {buf, len, 0};
	MXC_CRC_Compute(&req);
	return req.resultCRC;
/**
 * @brief Calculate the CRC32 of a buffer
 *
 * @tparam uint32_t Specialization for uint32_t
 * @param buf Buffer to calculate CRC32 of
 * @param len Length of buffer
 * @return uint32_t CRC32 of buffer
 */
template<> uint32_t calc_checksum<uint32_t>(uint32_t *buf, const uint32_t len) {
	if (MXC_CRC_Init() != E_NO_ERROR) { return 0; }
	MXC_CRC_SetPoly(0xEDB88320U);
	mxc_crc_req_t req = {buf, len, 0};
	MXC_CRC_Compute(&req);
	return req.resultCRC;
}
/**
 * @brief Calculate the CRC32 of a buffer
 *
 * @tparam uint32_t Specialization for uint32_t
 * @param buf Buffer to calculate CRC32 of
 * @param len Length of buffer
 * @return uint32_t CRC32 of buffer
 */
template<> uint32_t calc_checksum<uint32_t>(uint32_t *buf, const uint32_t len) {
	if (MXC_CRC_Init() != E_NO_ERROR) { return 0; }
	MXC_CRC_SetPoly(0xEDB88320U);
	mxc_crc_req_t req = {buf, len, 0};
	MXC_CRC_Compute(&req);
	return req.resultCRC;
}

#endif /* CRC32 */
