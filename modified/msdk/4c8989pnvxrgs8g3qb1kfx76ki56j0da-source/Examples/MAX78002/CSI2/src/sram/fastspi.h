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
#ifndef EXAMPLES_MAX78002_CSI2_SRC_SRAM_FASTSPI_H_
#define EXAMPLES_MAX78002_CSI2_SRC_SRAM_FASTSPI_H_

#include "fastspi_config.h"

static volatile bool g_tx_done = 0;
static volatile bool g_rx_done = 0;
static volatile bool g_master_done = 0;

static const mxc_gpio_cfg_t spi_ss_pin = { .port = SPI_SS_PORT,
                                           .mask = SPI_SS_PIN,
                                           .func = MXC_GPIO_FUNC_ALT1,
                                           .pad = MXC_GPIO_PAD_WEAK_PULL_UP,
                                           .vssel = MXC_GPIO_VSSEL_VDDIOH };

static const mxc_gpio_cfg_t spi_pins = { .port = SPI_PINS_PORT,
                                         .mask = SPI_PINS_MASK,
                                         .func = MXC_GPIO_FUNC_ALT1,
                                         .pad = MXC_GPIO_PAD_NONE,
                                         .vssel = MXC_GPIO_VSSEL_VDDIOH };

// TODO(Jake):  Generalize to multiple SPI instances
int spi_init();
int spi_transmit(uint8_t *src, uint32_t txlen, uint8_t *dest, uint32_t rxlen, bool deassert,
                 bool use_dma, bool block);

#endif // EXAMPLES_MAX78002_CSI2_SRC_SRAM_FASTSPI_H_
