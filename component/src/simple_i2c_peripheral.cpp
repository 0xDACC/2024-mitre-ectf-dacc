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
volatile uint8_t txbuf[bufsize] = {};
volatile uint8_t rxbuf[bufsize] = {};
volatile uint32_t txsize = 0;
volatile uint32_t rxcnt = 0;
volatile uint32_t txcnt = 0;
volatile i2c_cb_t processing_cb = nullptr;

error_t i2c_simple_peripheral_init(const uint8_t addr, const i2c_cb_t cb) {
    int error = 0;
    processing_cb = cb;

    error = MXC_I2C_Init(MXC_I2C1, false, addr);
    if (error != E_NO_ERROR) {
        printf("Failed to initialize I2C. %d\n", error);
        return error_t::ERROR;
    }

    MXC_I2C_SetFrequency(MXC_I2C1, I2C_FREQ);
    MXC_I2C_SetClockStretching(MXC_I2C1, 1);
    MXC_I2C_DisablePreload(MXC_I2C1);

    MXC_I2C_EnableInt(MXC_I2C1, MXC_F_I2C_INTFL0_RD_ADDR_MATCH, 0);
    MXC_I2C_EnableInt(MXC_I2C1, MXC_F_I2C_INTFL0_WR_ADDR_MATCH, 0);
    MXC_I2C_EnableInt(MXC_I2C1, MXC_F_I2C_INTFL0_STOP, 0);

    MXC_NVIC_SetVector(MXC_I2C_GET_IRQ(MXC_I2C_GET_IDX(MXC_I2C1)),
                       i2c_simple_isr);
    NVIC_EnableIRQ(MXC_I2C_GET_IRQ(MXC_I2C_GET_IDX(MXC_I2C1)));

    MXC_I2C_ClearFlags(MXC_I2C1, 0xFFFFFFFFU, 0xFFFFFFFFU);

    return error_t::SUCCESS;
}

void i2c_simple_isr() {
    const uint32_t flags = MXC_I2C1->intfl0;

    if ((flags & MXC_F_I2C_INTFL0_STOP) != 0) {
        printf("STOP\n");
        // Transaction ended
        const uint8_t available = MXC_I2C_GetRXFIFOAvailable(MXC_I2C1);
        if (available > (bufsize - rxcnt) && available != 0 &&
            rxcnt < bufsize) {
            rxcnt +=
                MXC_I2C_ReadRXFIFO(MXC_I2C1, rxbuf + rxcnt, bufsize - rxcnt);
        } else {
            rxcnt += MXC_I2C_ReadRXFIFO(MXC_I2C1, rxbuf + rxcnt, available);
        }

        MXC_I2C_DisableInt(MXC_I2C1, MXC_F_I2C_INTEN0_RX_THD, 0);
        MXC_I2C_DisableInt(MXC_I2C1, MXC_F_I2C_INTEN0_TX_THD, 0);

        if (MXC_I2C_GetRXFIFOAvailable(MXC_I2C1) != 0) {
            MXC_I2C_ClearRXFIFO(MXC_I2C1);
        }
        if (MXC_I2C_GetTXFIFOAvailable(MXC_I2C1) != 8) {
            MXC_I2C_ClearTXFIFO(MXC_I2C1);
        }
        // Reset state
        rxcnt = 0;
        txcnt = 0;

        MXC_I2C_ClearFlags(MXC_I2C1, MXC_F_I2C_INTFL0_STOP, 0);
    }

    if ((flags & MXC_F_I2C_INTEN0_TX_THD) != 0 &&
        (MXC_I2C1->inten0 & MXC_F_I2C_INTEN0_TX_THD) != 0) {
        printf("READ\n");
        // Master reading more from us

        if ((flags & MXC_F_I2C_INTFL0_TX_LOCKOUT) != 0) {
            MXC_I2C_ClearFlags(MXC_I2C1, MXC_F_I2C_INTFL0_TX_LOCKOUT, 0);
        }

        const uint8_t available = MXC_I2C_GetTXFIFOAvailable(MXC_I2C1);
        if (txsize == 0) {
            // Call the callback function
            printf("CALLING CALLBACK\n");
            if (call_processing_callback() != error_t::SUCCESS) {
                printf("Failed to call processing callback\n");
                return;
            }
            printf("CALLBACK SUCCESS\n");
        }
        printf("Available: %d\n", available);
        printf("TXCNT: %d\n", txcnt);
        printf("TXSIZE: %d\n", txsize);

        if (available > (txsize - txcnt) && txsize > 0 && txcnt < txsize) {
            txcnt +=
                MXC_I2C_WriteTXFIFO(MXC_I2C1, txbuf + txcnt, txsize - txcnt);
        } else if (txsize > 0) {
            txcnt += MXC_I2C_WriteTXFIFO(MXC_I2C1, txbuf + txcnt, available);
        }

        if (txcnt >= txsize && txsize > 0) {
            MXC_I2C_DisableInt(MXC_I2C1, MXC_F_I2C_INTEN0_TX_THD, 0);
        }

        MXC_I2C_ClearFlags(MXC_I2C1, MXC_F_I2C_INTFL0_TX_THD, 0);
    }

    if ((flags & MXC_F_I2C_INTFL0_WR_ADDR_MATCH) != 0) {
        printf("WRITE\n");
        // Master requested a read from us
        MXC_I2C_ClearFlags(MXC_I2C1, MXC_F_I2C_INTFL0_WR_ADDR_MATCH, 0);

        if ((flags & MXC_F_I2C_INTFL0_TX_LOCKOUT) != 0) {
            MXC_I2C_ClearFlags(MXC_I2C1, MXC_F_I2C_INTFL0_TX_LOCKOUT, 0);

            const uint8_t available = MXC_I2C_GetTXFIFOAvailable(MXC_I2C1);
            if (available > (txsize - txcnt) && txsize > 0 && txcnt < txsize) {
                txcnt += MXC_I2C_WriteTXFIFO(MXC_I2C1, txbuf + txcnt,
                                             txsize - txcnt);
            } else if (txsize > 0) {
                txcnt +=
                    MXC_I2C_WriteTXFIFO(MXC_I2C1, txbuf + txcnt, available);
            }

            MXC_I2C_EnableInt(MXC_I2C1, MXC_F_I2C_INTEN0_TX_THD, 0);
        }
    }

    if ((flags & MXC_F_I2C_INTFL0_RD_ADDR_MATCH) != 0) {
        printf("WRITE ST\n");
        // Master requested a write to us

        MXC_I2C_EnableInt(MXC_I2C1, MXC_F_I2C_INTEN0_RX_THD, 0);

        MXC_I2C_ClearFlags(MXC_I2C1, MXC_F_I2C_INTFL0_RD_ADDR_MATCH, 0);
    }

    if ((flags & MXC_F_I2C_INTEN0_RX_THD) != 0) {
        printf("READ ST\n");
        // Master writing more to us

        const uint8_t available = MXC_I2C_GetRXFIFOAvailable(MXC_I2C1);
        if (available > (bufsize - rxcnt)) {
            rxcnt +=
                MXC_I2C_ReadRXFIFO(MXC_I2C1, rxbuf + rxcnt, bufsize - rxcnt);
        } else {
            rxcnt += MXC_I2C_ReadRXFIFO(MXC_I2C1, rxbuf + rxcnt, available);
        }

        MXC_I2C_ClearFlags(MXC_I2C1, MXC_F_I2C_INTFL0_RX_THD, 0);
    }
}

void send_raw(const uint8_t *const buf, const uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) {
        txbuf[i] = buf[i];
    }
    txsize = len;
}

void clear() {
    for (uint32_t i = 0; i < bufsize; ++i) {
        txbuf[i] = 0;
        rxbuf[i] = 0;
    }
    txsize = 0;
    rxcnt = 0;
    txcnt = 0;
}

} // namespace i2c
