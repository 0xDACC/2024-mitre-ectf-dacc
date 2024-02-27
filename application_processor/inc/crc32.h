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
#include "mxc_device.h"

template <typename T> uint32_t calc_checksum(T *buf, const uint32_t len) {
    if (MXC_CRC_Init() != E_NO_ERROR) {
        return 0;
    }
    MXC_CRC_SetPoly(0xEDB88320U);
    mxc_crc_req_t req = {reinterpret_cast<uint32_t *>(buf), len, 0};
    MXC_CRC_Compute(&req);
    return req.resultCRC;
}

template <>
uint32_t calc_checksum<uint32_t>(uint32_t *buf, const uint32_t len) {
    if (MXC_CRC_Init() != E_NO_ERROR) {
        return 0;
    }
    MXC_CRC_SetPoly(0xEDB88320U);
    mxc_crc_req_t req = {buf, len, 0};
    MXC_CRC_Compute(&req);
    return req.resultCRC;
}
#endif
