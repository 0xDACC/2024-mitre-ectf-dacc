/**
 * @file simple_i2c_controller.cpp
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief Low Level I2C Communication Implementation
 * @version 0.1
 * @date 2024-02-01
 *
 * @copyright Copyright (c) 2024
 *
 */
#include "simple_i2c_controller.h"
#include "errors.h"
#include "i2c.h"
#include "mxc.h"
#include "nvic_table.h"
#include "packets.h"

namespace i2c {
error_t i2c_simple_controller_init() {

    // Initialize the I2C Interface
    const int error = MXC_I2C_Init(MXC_I2C1, true, 0);
    if (error != E_NO_ERROR) {
        printf("Failed to initialize I2C.\n");
        return error_t::ERROR;
    }

    MXC_I2C_SetFrequency(MXC_I2C1, I2C_FREQ);

    return error_t::SUCCESS;
}

template <packet_type_t R, packet_type_t T>
packet_t<R> send_i2c_tx(const i2c_addr_t addr, packet_t<T> packet) {
    uint8_t *const in = reinterpret_cast<uint8_t *>(&packet);
    uint8_t rxd[298] = {};
    packet_t<R> rxd_packet = {};

    mxc_i2c_req_t request;
    request.i2c = MXC_I2C1;
    request.addr = addr;
    request.tx_len = sizeof(packet_t<T>);
    request.tx_buf = in;
    request.rx_len = sizeof(packet_t<R>);
    request.rx_buf = rxd;
    request.restart = 0;
    request.callback = nullptr;

    if (MXC_I2C_MasterTransaction(&request) == E_NO_ERROR) {
        rxd_packet.header.magic = rxd[0];
        rxd_packet.header.checksum = reinterpret_cast<uint32_t *>(&rxd[1]);
        rxd_packet.payload = *reinterpret_cast<payload_t<R> *>(&rxd[5]);
        return rxd_packet;
    } else {
        packet_t<R> error;
        error.header.magic = packet_magic_t::ERROR;
        return error;
    }
}
} // namespace i2c
