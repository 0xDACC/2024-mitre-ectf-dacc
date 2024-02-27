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
using i2c_cb_t = error_t (*)(const uint8_t *const data,
                                   const uint32_t len);

/**
 * @brief ISR for the I2C Peripheral
 *
 * This ISR allows for a fully asynchronous interface between controller and
 * peripheral Transactions are able to begin immediately after a transaction
 * ends
 */
static void i2c_simple_isr();

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

/**
 * @brief Performs an I2C Transaction
 *
 */
class I2C_Handler {
  public:
    explicit I2C_Handler(const i2c_cb_t cb) : processing_cb(cb) {}

    ~I2C_Handler();
    /**
     * @brief Get the packet
     *
     * @tparam R Received packet type
     * @return packet_t<R> Received packet
     */
    template <packet_type_t R> packet_t<R> get_packet() {
        packet_t<R> packet;
        packet.header.magic = static_cast<packet_magic_t>(rxbuf[0]);
        memcpy(&packet.header.checksum, &rxbuf[1], 0x04);
        memcpy(&packet.payload, &rxbuf[5], sizeof(payload_t<R>));

        return packet;
    }

    /**
     * @brief Get the raw received data
     *
     * @param len Returns the length of the data
     * @return uint8_t* Pointer to the data
     */
    uint8_t *get_raw(uint32_t *const len) {
        *len = rxcnt;
        return rxbuf;
    }

    /**
     * @brief Set the raw TX buffer to a packet
     *
     * @tparam T The packet type
     * @param packet The packet to send
     */
    template <packet_type_t T> void send_packet(packet_t<T> packet) {
        txbuf[0] = static_cast<uint8_t>(packet.header.magic);

        memcpy(&txbuf[1], &packet.header.checksum, 0x04);
        memcpy(&txbuf[5], &packet.payload, sizeof(payload_t<T>));
        txsize = sizeof(packet_t<T>);
        rxsize = bufsize; // max size
    }

    /**
     * @brief Set the raw TX buffer
     *
     * @param buf The buffer to send
     * @param len The length of the buffer
     */
    void send_raw(const uint8_t *const buf, const uint32_t len) {
        for (uint32_t i = 0; i < len; ++i) {
            txbuf[i] = buf[i];
        }
        txsize = len;
        rxsize = bufsize; // max size
    }

    /**
     * @brief Append raw data to the RX buffer
     *
     * @param data The data to append
     * @param len The length of the data
     */
    void append_rx(const uint8_t *const data, uint8_t len) {
        if (len + rxcnt > rxsize) {
            len = rxsize - rxcnt;
        }
        for (uint8_t i = 0; i < len; ++i) {
            rxbuf[rxcnt + i] = data[i];
        }
        rxcnt += len;
    }

    /**
     * @brief Remove raw data from the TX buffer
     *
     * @param data Buffer to remove data to
     * @param len Length of the buffer
     */
    void remove_tx(uint8_t *const data, uint8_t *const len) {
        if (*len + txcnt > txsize) {
            *len = txsize - txcnt;
        }
        for (uint8_t i = 0; i < *len; ++i) {
            data[i] = txbuf[txcnt + i];
        }
        txcnt += *len;
    }

    /**
     * @brief Call the callback function
     *
     * @param success_callback The callback function called on success
     * @return mitre_error_t Whether the callback was successful
     *
     */
    error_t call_processing_callback() const {
        if (processing_cb == nullptr) {
            return error_t::SUCCESS;
        }
        return processing_cb(rxbuf, rxcnt);
    }

    /**
     * @brief Check if the TX is done
     *
     * @return bool Whether the TX is done
     */
    constexpr bool is_tx_done() const { return txcnt > txsize; }

    /**
     * @brief Check if the RX is done
     * @return bool Whether the RX is done
     */
    constexpr bool is_rx_done() const { return rxcnt > rxsize; }

    /**
     * @brief Get the size of the next receive block
     *
     * @param available The available space in the FIFO
     * @return constexpr uint32_t The size of the next receive block
     */
    constexpr uint32_t get_rx_size(const uint8_t available) const {
        return available < (rxsize - rxcnt) ? available : rxsize - rxcnt;
    }

    /**
     * @brief Clear the buffers to prepare for a new transaction
     *
     */
    void clear() {
        for (uint32_t i = 0; i < bufsize; ++i) {
            txbuf[i] = 0;
            rxbuf[i] = 0;
        }
        txsize = 0;
        rxsize = 0;
        rxcnt = 0;
        txcnt = 0;
    }

    /**
     * @brief Clear the RX counter
     *
     */
    void clear_rxcnt() { rxcnt = 0; }

    /**
     * @brief Clear the TX counter
     *
     */
    void clear_txcnt() { txcnt = 0; }

  private:
    static constexpr const uint32_t bufsize = 299;
    uint8_t txbuf[bufsize] = {};
    uint8_t rxbuf[bufsize] = {};
    uint32_t txsize = 0;
    uint32_t rxsize = 0;
    uint32_t rxcnt = 0;
    uint32_t txcnt = 0;
    i2c_cb_t processing_cb = nullptr;
};
/**
 * @brief Send a raw I2C transaction
 *
 * @param buffer Buffer to send
 * @param len Length of buffer, returns length of received data
 * @return uint8_t* Pointer to received data
 */
uint8_t *i2c_slave_raw_tx(uint8_t *buffer, uint32_t *len);

/**
 * @brief Global I2C Handler
 *
 */
extern I2C_Handler *handler;
} // namespace i2c

#endif /* SIMPLE_I2C_PERIPHERAL */
