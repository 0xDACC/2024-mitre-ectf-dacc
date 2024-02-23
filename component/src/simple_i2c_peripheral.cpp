/**
 * @file simple_i2c_peripheral.cpp
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief Low Level I2C Communication Implementation
 * @version 0.1
 * @date 2024-02-14
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "simple_i2c_peripheral.h"
#include "errors.h"
#include "i2c.h"
#include "mxc.h"
#include "packets.h"

namespace i2c {
volatile int I2C_FLAG = 1;
I2C_Handler *handler = nullptr;

mitre_error_t i2c_simple_peripheral_init(const uint8_t addr,
                                         const i2c_cb_t cb) {
    int error = 0;
    error = MXC_I2C_Init(MXC_I2C1, false, addr);
    if (error != E_NO_ERROR) {
        printf("Failed to initialize I2C.\n");
        return mitre_error_t::ERROR;
    }

    MXC_I2C_SetFrequency(MXC_I2C1, I2C_FREQ);
    MXC_I2C_SetClockStretching(MXC_I2C1, 1);
    MXC_I2C_DisablePreload(MXC_I2C1);

    handler = new I2C_Handler(cb);

    return mitre_error_t::SUCCESS;
}

int I2C_SlaveHandler(mxc_i2c_regs_t *const i2c,
                     const mxc_i2c_slave_event_t event, void *const data) {
    uint8_t buf[8] = {};
    uint32_t len = 0;

    switch (event) {
    case MXC_I2C_EVT_MASTER_WR:
        // Master will be writing to us
        handler->clear_rxcnt();
        break;

    case MXC_I2C_EVT_MASTER_RD:
        // Master will be reading from us, so call the callback to load data
        handler->clear_txcnt();
        i2c->intfl0 = MXC_F_I2C_INTFL0_TX_LOCKOUT | MXC_F_I2C_INTFL0_ADDR_MATCH;

        if (handler->call_processing_callback() != mitre_error_t::SUCCESS) {
            I2C_FLAG = E_COMM_ERR;
            return 1;
        }
        break;

    case MXC_I2C_EVT_RX_THRESH:
    case MXC_I2C_EVT_OVERFLOW:
        // Read as much data as possible from RX FIFO
        len += MXC_I2C_ReadRXFIFO(i2c, buf, MXC_I2C_GetRXFIFOAvailable(i2c));
        // Full buffer, receive done
        if (handler->append_rx(buf, len) == 0) {
            i2c->inten0 |= MXC_F_I2C_INTEN0_ADDR_MATCH;
        }

        break;

    case MXC_I2C_EVT_TX_THRESH:
    case MXC_I2C_EVT_UNDERFLOW:
        // Write as much data as possible into TX FIFO
        if (handler->is_tx_done()) {
            break;
        }
        len += handler->remove_tx(buf, MXC_I2C_GetTXFIFOAvailable(i2c));
        MXC_I2C_WriteTXFIFO(i2c, buf, len);
        break;

    default:
        if (*static_cast<int *const>(data) == E_COMM_ERR) {
            I2C_FLAG = E_COMM_ERR;
            return 1;
        } else if (*static_cast<int *const>(data) == E_NO_ERROR) {
            len +=
                MXC_I2C_ReadRXFIFO(i2c, buf, MXC_I2C_GetRXFIFOAvailable(i2c));
            handler->append_rx(buf, len);
            I2C_FLAG = E_NO_ERROR;
            return 1;
        }
    }

    return 0;
}

static uint8_t *i2c_slave_raw_tx(const uint8_t *const buffer,
                                 uint32_t *const len) {
    handler->clear();
    handler->send_raw(buffer, *len);
    I2C_FLAG = 1;

    if (MXC_I2C_SlaveTransaction(MXC_I2C1, I2C_SlaveHandler) == E_NO_ERROR) {
        return handler->get_raw(len);
    } else {
        return nullptr;
    }
}
} // namespace i2c
