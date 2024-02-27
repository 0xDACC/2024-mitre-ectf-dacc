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
I2C_Handler *handler = nullptr;

error_t i2c_simple_peripheral_init(const uint8_t addr, const i2c_cb_t cb) {
    int error = 0;
    handler = new I2C_Handler(cb);

    error = MXC_I2C_Init(MXC_I2C1, false, addr);
    if (error != E_NO_ERROR) {
        printf("Failed to initialize I2C. %d\n", error);
        return error_t::ERROR;
    } else {
        printf("I2C initialized\n");
    }

    MXC_I2C_SetFrequency(MXC_I2C1, I2C_FREQ);
    MXC_I2C_SetClockStretching(MXC_I2C1, 1);
    MXC_I2C_DisablePreload(MXC_I2C1);

    MXC_I2C_EnableInt(MXC_I2C1, MXC_F_I2C_INTFL0_RD_ADDR_MATCH, 0);
    MXC_I2C_EnableInt(MXC_I2C1, MXC_F_I2C_INTFL0_WR_ADDR_MATCH, 0);
    MXC_I2C_EnableInt(MXC_I2C1, MXC_F_I2C_INTFL0_STOP, 0);

    MXC_NVIC_SetVector(I2C1_IRQn, i2c_simple_isr);
    NVIC_EnableIRQ(I2C1_IRQn);

    MXC_I2C_ClearFlags(MXC_I2C1, 0xFFFFFFFFU, 0xFFFFFFFFU);

    return error_t::SUCCESS;
}

void i2c_simple_isr() {
    printf("Inside ISR");
    uint8_t buf[8] = {};
    uint32_t len = 0;

    const uint32_t flags = MXC_I2C1->intfl0;
    const uint32_t ints = MXC_I2C1->inten0;

    if ((flags & MXC_F_I2C_INTFL0_STOP) != 0) {
        // Transaction ended
        const uint8_t available = MXC_I2C_GetRXFIFOAvailable(MXC_I2C1);
        const uint8_t size = handler->get_rx_size(available);
        len += MXC_I2C_ReadRXFIFO(MXC_I2C1, buf, size);
        handler->append_rx(buf, len);

        MXC_I2C_DisableInt(MXC_I2C1, MXC_F_I2C_INTEN0_RX_THD, 0);
        MXC_I2C_DisableInt(MXC_I2C1, MXC_F_I2C_INTEN0_TX_THD, 0);

        if (MXC_I2C_GetRXFIFOAvailable(MXC_I2C1) != 0) {
            MXC_I2C_ClearRXFIFO(MXC_I2C1);
        }
        if (MXC_I2C_GetTXFIFOAvailable(MXC_I2C1) != 8) {
            MXC_I2C_ClearTXFIFO(MXC_I2C1);
        }

        // Reset state
        handler->clear_rxcnt();
        handler->clear_txcnt();

        MXC_I2C_ClearFlags(MXC_I2C1, MXC_F_I2C_INTFL0_STOP, 0);
    }

    if ((flags & MXC_F_I2C_INTEN0_TX_THD) != 0 &&
        (ints & MXC_F_I2C_INTEN0_TX_THD) != 0) {
        // Master reading more from us

        if ((flags & MXC_F_I2C_INTFL0_TX_LOCKOUT) != 0) {
            MXC_I2C_ClearFlags(MXC_I2C1, MXC_F_I2C_INTFL0_TX_LOCKOUT, 0);
        }

        uint8_t size = MXC_I2C_GetTXFIFOAvailable(MXC_I2C1);
        handler->remove_tx(buf, &size);
        MXC_I2C_WriteTXFIFO(MXC_I2C1, buf, size);

        if (handler->is_tx_done()) {
            MXC_I2C_DisableInt(MXC_I2C1, MXC_F_I2C_INTEN0_TX_THD, 0);
        }

        MXC_I2C_ClearFlags(MXC_I2C1, MXC_F_I2C_INTFL0_TX_THD, 0);
    }

    if ((flags & MXC_F_I2C_INTFL0_WR_ADDR_MATCH) != 0) {
        // Master requested a read from us
        if (handler->call_processing_callback() != error_t::SUCCESS) {
            return;
        }

        MXC_I2C_ClearFlags(MXC_I2C1, MXC_F_I2C_INTFL0_WR_ADDR_MATCH, 0);

        if ((flags & MXC_F_I2C_INTFL0_TX_LOCKOUT) != 0) {
            MXC_I2C_ClearFlags(MXC_I2C1, MXC_F_I2C_INTFL0_TX_LOCKOUT, 0);

            uint8_t size = MXC_I2C_GetTXFIFOAvailable(MXC_I2C1);
            handler->remove_tx(buf, &size);
            MXC_I2C_WriteTXFIFO(MXC_I2C1, buf, size);

            MXC_I2C_EnableInt(MXC_I2C1, MXC_F_I2C_INTEN0_TX_THD, 0);
        }
    }

    if ((flags & MXC_F_I2C_INTFL0_RD_ADDR_MATCH) != 0) {
        // Master requested a write to us

        MXC_I2C_EnableInt(MXC_I2C1, MXC_F_I2C_INTEN0_RX_THD, 0);

        MXC_I2C_ClearFlags(MXC_I2C1, MXC_F_I2C_INTFL0_RD_ADDR_MATCH, 0);
    }

    if ((flags & MXC_F_I2C_INTEN0_RX_THD) != 0) {
        // Master writing more to us

        const uint8_t available = MXC_I2C_GetRXFIFOAvailable(MXC_I2C1);
        const uint8_t size = handler->get_rx_size(available);
        len += MXC_I2C_ReadRXFIFO(MXC_I2C1, buf, size);
        handler->append_rx(buf, len);

        MXC_I2C_ClearFlags(MXC_I2C1, MXC_F_I2C_INTFL0_RX_THD, 0);
    }
}

} // namespace i2c
