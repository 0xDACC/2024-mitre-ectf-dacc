/**
 * @file simple_i2c_controller.h
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief Low Level I2C Communication Interface
 * @version 0.1
 * @date 2024-02-01
 *
 * @copyright Copyright (c) 2024
 *
 */

#ifndef __SIMPLE_I2C_CONTROLLER__
#define __SIMPLE_I2C_CONTROLLER__

#include "errors.h"
#include "packets.h"
#include "stdint.h"

namespace i2c {
// I2C frequency in HZ
constexpr const uint32_t I2C_FREQ = 100000;

using i2c_addr_t = uint8_t;

/**
 * @brief Initialize the I2C Connection
 *
 */
error_t i2c_simple_controller_init();

/**
 * @brief Perform an I2C Transaction
 *
 * @tparam R Expected packet type
 * @tparam T Packet type to send
 * @param addr I2C Address
 * @param packet Packet to send
 * @return packet_t<R> Received packet
 */
template <packet_type_t R, packet_type_t T>
packet_t<R> send_i2c_tx(const i2c_addr_t addr, packet_t<T> packet);
} // namespace i2c

#endif
