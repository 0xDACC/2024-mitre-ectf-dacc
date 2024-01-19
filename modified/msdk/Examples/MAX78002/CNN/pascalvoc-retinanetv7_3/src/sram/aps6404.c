/******************************************************************************
 * Copyright (C) 2023 Maxim Integrated Products, Inc., All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL MAXIM INTEGRATED BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Except as contained in this notice, the name of Maxim Integrated
 * Products, Inc. shall not be used except as stated in the Maxim Integrated
 * Products, Inc. Branding Policy.
 *
 * The mere transfer of this software does not imply any licenses
 * of trade secrets, proprietary technology, copyrights, patents,
 * trademarks, maskwork rights, or any other form of intellectual
 * property whatsoever. Maxim Integrated Products, Inc. retains all
 * ownership rights.
 *
 ******************************************************************************/

#include <stdint.h>
#include <string.h> // For memset
#include "aps6404.h"
#include "mxc_errors.h"
#include "mxc_delay.h"
#include "fastspi.h"
#include "tmr.h"

enum MODE { STANDARD_MODE, QUAD_MODE };
typedef enum MODE MODE_t;
MODE_t g_current_mode;

inline void _parse_spi_header(uint8_t cmd, uint32_t address, uint8_t *out)
{
    out[0] = cmd;
    out[1] = (address >> 16) & 0xFF; // MSB first
    out[2] = (address >> 8) & 0xFF;
    out[3] = (address & 0xFF);
}

int _transmit_spi_header(uint8_t cmd, uint32_t address)
{
    int err = E_NO_ERROR;
    // SPI reads and writes will always start with 4 bytes.
    // A command byte, then a 24-bit address (MSB first)
    uint8_t header[4];
    _parse_spi_header(cmd, address, header);

    // Transmit header, but keep Chip Select asserted.
    spi_transmit(header, 4, NULL, 0, false, true, true);
    return err;
}

int ram_init()
{
    int err = E_NO_ERROR;
    err = spi_init();
    if (err)
        return err;

    err = ram_exit_quadmode(); // Protect against quad-mode lock-up
    if (err)
        return err;

    err = ram_reset();
    return err;
}

int ram_reset()
{
    int err = E_NO_ERROR;
    uint8_t data[2] = { 0x66, 0x99 };

    spi_transmit(&data[0], 1, NULL, 0, true, true, true);
    spi_transmit(&data[1], 1, NULL, 0, true, true, true);

    return err;
}

int ram_enter_quadmode()
{
    int err = E_NO_ERROR;
    uint8_t tx_data = 0x35;

    MXC_SPI_SetWidth(SPI, SPI_WIDTH_STANDARD);
    spi_transmit(&tx_data, 1, NULL, 0, true, true, true);
    MXC_SPI_SetWidth(SPI, SPI_WIDTH_QUAD);

    g_current_mode = QUAD_MODE;

    return err;
}

int ram_exit_quadmode()
{
    int err = E_NO_ERROR;
    uint8_t tx_data = 0xF5;

    MXC_SPI_SetWidth(SPI, SPI_WIDTH_QUAD);
    spi_transmit(&tx_data, 1, NULL, 0, true, true, true);
    MXC_SPI_SetWidth(SPI, SPI_WIDTH_STANDARD);

    g_current_mode = STANDARD_MODE;

    return err;
}

int ram_read_id(ram_id_t *out)
{
    int err = E_NO_ERROR;
    uint8_t tx_data = 0x9F;
    uint8_t rx_data[12];

    if (g_current_mode != STANDARD_MODE)
        ram_exit_quadmode();

    spi_transmit(&tx_data, 1, NULL, 0, false, true, true);
    spi_transmit(NULL, 0, rx_data, 12, true, true, true);

    out->MFID = rx_data[3];
    out->KGD = rx_data[4];
    out->density = (rx_data[5] & 0xe0) >> 5; // Density is just top 3 bits

    // Formulate 44-bit EID from remaining bytes
    int tmp = rx_data[5] & 0x1F;
    for (int i = 0; i <= 6; i++) {
        tmp = tmp << 8;
        tmp |= rx_data[5 + i];
    }
    out->EID = tmp;

    // Validate against expected values
    if (out->MFID != MFID_EXPECTED)
        return E_INVALID;
    if (out->KGD != KGD_EXPECTED)
        return E_INVALID;
    if (out->density != DENSITY_EXPECTED)
        return E_INVALID;

    return err;
}

int ram_read_slow(uint32_t address, uint8_t *out, unsigned int len)
{
    if (g_current_mode != STANDARD_MODE)
        ram_exit_quadmode();

    int err = E_NO_ERROR;
    err = _transmit_spi_header(0x03, address);
    if (err)
        return err;

    return spi_transmit(NULL, 0, out, len, true, true, true);
}

int ram_read_quad(uint32_t address, uint8_t *out, unsigned int len)
{
    if (g_current_mode != QUAD_MODE)
        ram_enter_quadmode();

    int err = E_NO_ERROR;
    uint8_t header[7];
    memset(header, 0xFF, 7);
    // ^ Sending dummy bytes with value 0x00 seems to break QSPI reads...  Sending 0xFF works
    _parse_spi_header(0xEB, address, header);

    err = spi_transmit(&header[0], 7, NULL, 0, false, true, true);
    err = spi_transmit(NULL, 0, out, len, true, true, true);
    return err;
}

int ram_write(uint32_t address, uint8_t *data, unsigned int len)
{
    if (g_current_mode != STANDARD_MODE)
        ram_exit_quadmode();

    int err = E_NO_ERROR;
    err = _transmit_spi_header(0x02, address);
    if (err)
        return err;

    return spi_transmit(data, len, NULL, 0, true, true, true);
}

int ram_write_quad(uint32_t address, uint8_t *data, unsigned int len)
{
    if (g_current_mode != QUAD_MODE)
        ram_enter_quadmode();

    int err = E_NO_ERROR;
    err = _transmit_spi_header(0x38, address);
    if (err)
        return err;

    return spi_transmit(data, len, NULL, 0, true, true, true);
}

int benchmark_dma_overhead(unsigned int *out)
{
    uint8_t buffer[5];
    _parse_spi_header(0x02, 0x0, buffer);

    MXC_TMR_SW_Start(MXC_TMR0);
    spi_transmit(buffer, 5, NULL, 0, true, true, false);
    unsigned int elapsed = MXC_TMR_SW_Stop(MXC_TMR0);

    *out = elapsed;
    return E_NO_ERROR;
}