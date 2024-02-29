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

#ifndef SIMPLE_I2C_PERIPHERAL
#define SIMPLE_I2C_PERIPHERAL

#include "errors.h"
#include "i2c.h"
#include "mxc.h"
#include "packets.h"
#include <stdint.h>

namespace i2c {
constexpr const uint32_t I2C_FREQ = 100000;

using i2c_addr_t = uint8_t;
using i2c_cb_t = error_t (*)(const uint8_t *const);

/**
 * @brief ISR for the I2C Peripheral
 *
 * This ISR allows for a fully asynchronous interface between controller and
 * peripheral Transactions are able to begin immediately after a transaction
 * ends
 */
void i2c_simple_isr();

/**
 * @brief Initialize the I2C Connection
 *
 * @param addr I2C Address
 * @param cb Callback function for processing received data
 */
error_t i2c_simple_peripheral_init(uint8_t addr, i2c_cb_t cb);

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

static constexpr const uint32_t bufsize = 299;

extern volatile uint8_t txbuf[bufsize];
extern volatile uint8_t rxbuf[bufsize];
extern volatile uint32_t txsize;
extern volatile uint32_t rxcnt;
extern volatile uint32_t txcnt;
extern volatile i2c_cb_t processing_cb;

/**
 * @brief Set the raw TX buffer to a packet
 *
 * @tparam T The packet type
 * @param packet The packet to send
 */
template <packet_type_t T> void send_packet(packet_t<T> packet) {
    txbuf[0] = static_cast<uint8_t>(packet.header.magic);

    memcpy(const_cast<uint8_t *>(&txbuf[1]), &packet.header.checksum, 0x04);
    memcpy(const_cast<uint8_t *>(&txbuf[5]), &packet.payload,
           sizeof(payload_t<T>));
    txsize = sizeof(payload_t<T>) + sizeof(packet_magic_t) + sizeof(uint32_t);
}

/**
 * @brief Set the raw TX buffer
 *
 * @param buf The buffer to send
 * @param len The length of the buffer
 */
void send_raw(const uint8_t *const buf, const uint32_t len);

/**
 * @brief Call the callback function
 *
 * @param success_callback The callback function called on success
 * @return mitre_error_t Whether the callback was successful
 *
 */
inline error_t call_processing_callback() {
    if (processing_cb == nullptr) {
        return error_t::ERROR;
    }
    return processing_cb(const_cast<uint8_t *>(rxbuf));
}

/**
 * @brief Clear the buffers to prepare for a new transaction
 *
 */
void clear();

/**
 * @brief Send a raw I2C transaction
 *
 * @param buffer Buffer to send
 * @param len Length of buffer, returns length of received data
 * @return uint8_t* Pointer to received data
 */
uint8_t *i2c_slave_raw_tx(uint8_t *buffer, uint32_t *len);

} // namespace i2c

#endif /* SIMPLE_I2C_PERIPHERAL */
