/**
 * @file mxc_pins.c
 * @brief      This file contains constant pin configurations for the peripherals.
 */

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

#include "gpio.h"
#include "mxc_device.h"

/***** Definitions *****/

/***** Global Variables *****/
const mxc_gpio_cfg_t gpio_cfg_i2c0 = { MXC_GPIO0, (MXC_GPIO_PIN_9 | MXC_GPIO_PIN_10),
                                       MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE,
                                       MXC_GPIO_VSSEL_VDDIO };

const mxc_gpio_cfg_t gpio_cfg_uart0 = { MXC_GPIO0, (MXC_GPIO_PIN_0 | MXC_GPIO_PIN_1),
                                        MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE,
                                        MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_uart0_flow = { MXC_GPIO1, (MXC_GPIO_PIN_8 | MXC_GPIO_PIN_9),
                                             MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE,
                                             MXC_GPIO_VSSEL_VDDIO };

const mxc_gpio_cfg_t gpio_cfg_spi0 = {
    MXC_GPIO0, (MXC_GPIO_PIN_2 | MXC_GPIO_PIN_3 | MXC_GPIO_PIN_4 | MXC_GPIO_PIN_7 | MXC_GPIO_PIN_8),
    MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO
};
const mxc_gpio_cfg_t gpio_cfg_spi0_ss0 = { MXC_GPIO0, (MXC_GPIO_PIN_5), MXC_GPIO_FUNC_ALT1,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi0_ss1 = { MXC_GPIO0, (MXC_GPIO_PIN_6), MXC_GPIO_FUNC_ALT1,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };

const mxc_gpio_cfg_t gpio_cfg_spi1 = {
    MXC_GPIO0, (MXC_GPIO_PIN_11 | MXC_GPIO_PIN_12 | MXC_GPIO_PIN_13 | MXC_GPIO_PIN_14),
    MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO
};
const mxc_gpio_cfg_t gpio_cfg_spi1_ss0 = { MXC_GPIO0, (MXC_GPIO_PIN_14), MXC_GPIO_FUNC_ALT1,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi1_ss1 = { MXC_GPIO0, (MXC_GPIO_PIN_15), MXC_GPIO_FUNC_ALT1,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi1_ss2 = { MXC_GPIO1, (MXC_GPIO_PIN_6), MXC_GPIO_FUNC_ALT2,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi1_ss3 = { MXC_GPIO1, (MXC_GPIO_PIN_7), MXC_GPIO_FUNC_ALT2,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };

const mxc_gpio_cfg_t gpio_cfg_tmr0 = { MXC_GPIO1, MXC_GPIO_PIN_0, MXC_GPIO_FUNC_ALT1,
                                       MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_tmr1 = { MXC_GPIO1, MXC_GPIO_PIN_1, MXC_GPIO_FUNC_ALT1,
                                       MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_tmr2 = { MXC_GPIO1, MXC_GPIO_PIN_6, MXC_GPIO_FUNC_ALT1,
                                       MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_tmr3 = { MXC_GPIO1, MXC_GPIO_PIN_7, MXC_GPIO_FUNC_ALT1,
                                       MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };

const mxc_gpio_cfg_t gpio_cfg_sfe = {
    MXC_GPIO0, (MXC_GPIO_PIN_2 | MXC_GPIO_PIN_3 | MXC_GPIO_PIN_4 | MXC_GPIO_PIN_7 | MXC_GPIO_PIN_8),
    MXC_GPIO_FUNC_ALT2, MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO
};
const mxc_gpio_cfg_t gpio_cfg_sfe_ss0 = { MXC_GPIO0, (MXC_GPIO_PIN_5), MXC_GPIO_FUNC_ALT2,
                                          MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_sfe_ss1 = { MXC_GPIO0, (MXC_GPIO_PIN_6), MXC_GPIO_FUNC_ALT2,
                                          MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };

// SPI v2 Pin Definitions
const mxc_gpio_cfg_t gpio_cfg_spi0_standard = { MXC_GPIO0,
                                                (MXC_GPIO_PIN_2 | MXC_GPIO_PIN_3 | MXC_GPIO_PIN_4),
                                                MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE,
                                                MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi0_3wire = { MXC_GPIO0, (MXC_GPIO_PIN_2 | MXC_GPIO_PIN_4),
                                             MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE,
                                             MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi0_dual = { MXC_GPIO0,
                                            (MXC_GPIO_PIN_2 | MXC_GPIO_PIN_3 | MXC_GPIO_PIN_4),
                                            MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE,
                                            MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi0_quad = {
    MXC_GPIO0, (MXC_GPIO_PIN_2 | MXC_GPIO_PIN_3 | MXC_GPIO_PIN_4 | MXC_GPIO_PIN_7 | MXC_GPIO_PIN_8),
    MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO
};

const mxc_gpio_cfg_t gpio_cfg_spi1_standard = {
    MXC_GPIO0, (MXC_GPIO_PIN_11 | MXC_GPIO_PIN_12 | MXC_GPIO_PIN_13), MXC_GPIO_FUNC_ALT1,
    MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO
};
const mxc_gpio_cfg_t gpio_cfg_spi1_3wire = { MXC_GPIO0, (MXC_GPIO_PIN_12 | MXC_GPIO_PIN_13),
                                             MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE,
                                             MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi1_dual = { MXC_GPIO0,
                                            (MXC_GPIO_PIN_11 | MXC_GPIO_PIN_12 | MXC_GPIO_PIN_13),
                                            MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE,
                                            MXC_GPIO_VSSEL_VDDIO };
// Quad SPI not supported on MXC_SPI1.

// SPI v2 Target Selects Pin Definitions
const mxc_gpio_cfg_t gpio_cfg_spi0_ts0 = { MXC_GPIO0, MXC_GPIO_PIN_5, MXC_GPIO_FUNC_ALT1,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi0_ts1 = { MXC_GPIO0, MXC_GPIO_PIN_6, MXC_GPIO_FUNC_ALT2,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi1_ts0 = { MXC_GPIO0, MXC_GPIO_PIN_14, MXC_GPIO_FUNC_ALT1,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi1_ts1 = { MXC_GPIO0, MXC_GPIO_PIN_15, MXC_GPIO_FUNC_ALT1,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi1_ts2 = { MXC_GPIO1, MXC_GPIO_PIN_6, MXC_GPIO_FUNC_ALT1,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi1_ts3 = { MXC_GPIO1, MXC_GPIO_PIN_7, MXC_GPIO_FUNC_ALT1,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
