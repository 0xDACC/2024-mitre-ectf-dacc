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

#ifndef SIMPLE_I2C_CONTROLLER
#define SIMPLE_I2C_CONTROLLER

#include "errors.h"
#include "host_messaging.h"
#include "mxc.h"
#include "packets.h"

#include <stdint.h>

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
    template<packet_type_t R, packet_type_t T>
    packet_t<R> send_i2c_master_tx(const i2c_addr_t addr, packet_t<T> packet) {
        uint8_t rxbuf[256] = {};
        uint8_t txbuf[256] = {};
        packet_t<R> rx_packet = {};

        memcpy(&txbuf[0], &packet.header.magic, sizeof(packet_magic_t));
        memcpy(&txbuf[1], &packet.header.checksum, sizeof(uint32_t));
        memcpy(&txbuf[5], &packet.payload, sizeof(payload_t<T>));

        mxc_i2c_req_t request;
        request.i2c = MXC_I2C1;
        request.addr = addr;
        request.tx_len = 256;
        request.tx_buf = txbuf;
        request.rx_len = 256;
        request.rx_buf = rxbuf;
        request.restart = 0;
        request.callback = nullptr;

        const int error = MXC_I2C_MasterTransaction(&request);
        if (error == E_NO_ERROR) {
            rx_packet.header.magic = static_cast<packet_magic_t>(rxbuf[0]);
            memcpy(&rx_packet.header.checksum, &rxbuf[1], sizeof(uint32_t));
            memcpy(&rx_packet.payload, &rxbuf[5], sizeof(payload_t<R>));
            return rx_packet;
        } else {
            packet_t<R> error_packet = {};
            error_packet.header.magic = packet_magic_t::ERROR;
            return error_packet;
        }
    }

    /**
     * @brief Convert 4-byte component ID to I2C address
     *
     * @param component_id component_id to convert
     *
     * @return i2c_addr_t, i2c address
     */
    constexpr i2c_addr_t component_id_to_i2c_addr(const uint32_t component_id) {
        return component_id & 0xFF;
    }

}  // namespace i2c

#endif /* SIMPLE_I2C_CONTROLLER */
