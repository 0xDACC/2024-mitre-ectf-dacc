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

#include "crc.h"
#include "mxc.h"

#include <string.h>

uint32_t prev_crc = 0;
/**
 * @brief Calculate the CRC32 of a buffer
 *
 * @tparam T Type of buffer
 * @param buf Buffer to calculate CRC32 of
 * @param len Length of buffer
 * @return uint32_t CRC32 of buffer
 */
template<typename T> uint32_t calc_checksum(T *buf, const uint32_t len) {
    if (len > 256) { return 0; }
    uint32_t _buf[64] = {};
    memcpy(_buf, buf, len);
    if (MXC_CRC_Init() != E_NO_ERROR) { return 0; }
    MXC_CRC_SetPoly(0xEDB88320U);
    mxc_crc_req_t req = {_buf, 64, prev_crc};
    if (MXC_CRC_Compute(&req) != E_NO_ERROR) { return 0; }
    if (MXC_CRC_Shutdown() != E_NO_ERROR) { return 0; }
    prev_crc = req.resultCRC;
    return req.resultCRC;
}

template<typename T>
uint32_t calc_checksum(const T *const buf, const uint32_t len) {
    if (len > 256) { return 0; }
    uint32_t _buf[64] = {};
    memcpy(_buf, buf, len);
    if (MXC_CRC_Init() != E_NO_ERROR) { return 0; }
    MXC_CRC_SetPoly(0xEDB88320U);
    mxc_crc_req_t req = {_buf, 64, prev_crc};
    if (MXC_CRC_Compute(&req) != E_NO_ERROR) { return 0; }
    if (MXC_CRC_Shutdown() != E_NO_ERROR) { return 0; }
    prev_crc = req.resultCRC;
    return req.resultCRC;
}

#endif /* CRC32 */
