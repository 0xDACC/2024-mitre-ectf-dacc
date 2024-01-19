/**
 * @file    mxc_pins.c
 * @brief   This file contains constant pin configurations for the peripherals.
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
const mxc_gpio_cfg_t gpio_cfg_lp_extclk = { MXC_GPIO0, (MXC_GPIO_PIN_11), MXC_GPIO_FUNC_ALT5,
                                            MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_hf_extclk = { MXC_GPIO0, (MXC_GPIO_PIN_6), MXC_GPIO_FUNC_ALT4,
                                            MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };

const mxc_gpio_cfg_t gpio_cfg_i2c0 = { MXC_GPIO0, (MXC_GPIO_PIN_12 | MXC_GPIO_PIN_13),
                                       MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE,
                                       MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_i2c1 = { MXC_GPIO0, (MXC_GPIO_PIN_6 | MXC_GPIO_PIN_9),
                                       MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE,
                                       MXC_GPIO_VSSEL_VDDIO };

const mxc_gpio_cfg_t gpio_cfg_uart0 = { MXC_GPIO0, (MXC_GPIO_PIN_10 | MXC_GPIO_PIN_11),
                                        MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_WEAK_PULL_UP,
                                        MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_uart0_flow = { MXC_GPIO0, (MXC_GPIO_PIN_19 | MXC_GPIO_PIN_20),
                                             MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_WEAK_PULL_UP,
                                             MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_uart0_flow_disable = { MXC_GPIO0, (MXC_GPIO_PIN_19 | MXC_GPIO_PIN_20),
                                                     MXC_GPIO_FUNC_IN, MXC_GPIO_PAD_WEAK_PULL_UP,
                                                     MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_uart0b = { MXC_GPIO0, (MXC_GPIO_PIN_7 | MXC_GPIO_PIN_8),
                                         MXC_GPIO_FUNC_ALT4, MXC_GPIO_PAD_WEAK_PULL_UP,
                                         MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_uart0b_flow = { MXC_GPIO0, (MXC_GPIO_PIN_17 | MXC_GPIO_PIN_18),
                                              MXC_GPIO_FUNC_ALT4, MXC_GPIO_PAD_WEAK_PULL_UP,
                                              MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_uart0b_flow_disable = { MXC_GPIO0,
                                                      (MXC_GPIO_PIN_17 | MXC_GPIO_PIN_18),
                                                      MXC_GPIO_FUNC_IN, MXC_GPIO_PAD_WEAK_PULL_UP,
                                                      MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_uart1 = { MXC_GPIO0, (MXC_GPIO_PIN_2 | MXC_GPIO_PIN_3),
                                        MXC_GPIO_FUNC_ALT2, MXC_GPIO_PAD_WEAK_PULL_UP,
                                        MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_uart1_flow = { MXC_GPIO0, (MXC_GPIO_PIN_4 | MXC_GPIO_PIN_5),
                                             MXC_GPIO_FUNC_ALT2, MXC_GPIO_PAD_WEAK_PULL_UP,
                                             MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_uart1_flow_disable = { MXC_GPIO0, (MXC_GPIO_PIN_4 | MXC_GPIO_PIN_5),
                                                     MXC_GPIO_FUNC_IN, MXC_GPIO_PAD_WEAK_PULL_UP,
                                                     MXC_GPIO_VSSEL_VDDIO };

// Timers are only defined once, depending on package, each timer could be mapped to other pins
const mxc_gpio_cfg_t gpio_cfg_tmr0 = { MXC_GPIO0, (MXC_GPIO_PIN_2 | MXC_GPIO_PIN_3),
                                       MXC_GPIO_FUNC_ALT3, MXC_GPIO_PAD_NONE,
                                       MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_tmr0b = { MXC_GPIO0, (MXC_GPIO_PIN_0 | MXC_GPIO_PIN_1),
                                        MXC_GPIO_FUNC_ALT3, MXC_GPIO_PAD_NONE,
                                        MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_tmr0c = { MXC_GPIO0, (MXC_GPIO_PIN_15 | MXC_GPIO_PIN_16),
                                        MXC_GPIO_FUNC_ALT4, MXC_GPIO_PAD_NONE,
                                        MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_tmr1 = { MXC_GPIO0, (MXC_GPIO_PIN_4 | MXC_GPIO_PIN_5),
                                       MXC_GPIO_FUNC_ALT3, MXC_GPIO_PAD_NONE,
                                       MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_tmr1b = { MXC_GPIO0, (MXC_GPIO_PIN_19 | MXC_GPIO_PIN_20),
                                        MXC_GPIO_FUNC_ALT3, MXC_GPIO_PAD_NONE,
                                        MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_tmr1c = { MXC_GPIO0, (MXC_GPIO_PIN_0 | MXC_GPIO_PIN_1),
                                        MXC_GPIO_FUNC_ALT4, MXC_GPIO_PAD_NONE,
                                        MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_tmr2 = { MXC_GPIO0, (MXC_GPIO_PIN_6 | MXC_GPIO_PIN_9),
                                       MXC_GPIO_FUNC_ALT3, MXC_GPIO_PAD_NONE,
                                       MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_tmr2b = { MXC_GPIO0, (MXC_GPIO_PIN_7 | MXC_GPIO_PIN_8),
                                        MXC_GPIO_FUNC_ALT3, MXC_GPIO_PAD_NONE,
                                        MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_tmr2c = { MXC_GPIO0, (MXC_GPIO_PIN_15 | MXC_GPIO_PIN_16),
                                        MXC_GPIO_FUNC_ALT3, MXC_GPIO_PAD_NONE,
                                        MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_tmr3 = { MXC_GPIO0, (MXC_GPIO_PIN_12 | MXC_GPIO_PIN_13),
                                       MXC_GPIO_FUNC_ALT3, MXC_GPIO_PAD_NONE,
                                       MXC_GPIO_VSSEL_VDDIO };

const mxc_gpio_cfg_t gpio_cfg_i2s = {
    MXC_GPIO0, (MXC_GPIO_PIN_2 | MXC_GPIO_PIN_3 | MXC_GPIO_PIN_4 | MXC_GPIO_PIN_5),
    MXC_GPIO_FUNC_ALT5, MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO
};

const mxc_gpio_cfg_t gpio_cfg_spi0 = { MXC_GPIO0,
                                       (MXC_GPIO_PIN_2 | MXC_GPIO_PIN_3 | MXC_GPIO_PIN_4),
                                       MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE,
                                       MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi0_ss0 = { MXC_GPIO0, (MXC_GPIO_PIN_5), MXC_GPIO_FUNC_ALT1,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };

const mxc_gpio_cfg_t gpio_cfg_spi1 = { MXC_GPIO0,
                                       (MXC_GPIO_PIN_7 | MXC_GPIO_PIN_8 | MXC_GPIO_PIN_17),
                                       MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE,
                                       MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi1_ss0 = { MXC_GPIO0, (MXC_GPIO_PIN_18), MXC_GPIO_FUNC_ALT1,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi1b = { MXC_GPIO0,
                                        (MXC_GPIO_PIN_11 | MXC_GPIO_PIN_12 | MXC_GPIO_PIN_13),
                                        MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE,
                                        MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi1b_ss0 = { MXC_GPIO0, (MXC_GPIO_PIN_10), MXC_GPIO_FUNC_ALT1,
                                            MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };

const mxc_gpio_cfg_t gpio_cfg_pt0 = { MXC_GPIO0, MXC_GPIO_PIN_2, MXC_GPIO_FUNC_ALT4,
                                      MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_pt1 = { MXC_GPIO0, MXC_GPIO_PIN_3, MXC_GPIO_FUNC_ALT4,
                                      MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_pt2 = { MXC_GPIO0, MXC_GPIO_PIN_4, MXC_GPIO_FUNC_ALT4,
                                      MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_pt3 = { MXC_GPIO0, MXC_GPIO_PIN_5, MXC_GPIO_FUNC_ALT4,
                                      MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };

const mxc_gpio_cfg_t gpio_cfg_adc_ain0 = { MXC_GPIO0, MXC_GPIO_PIN_13, MXC_GPIO_FUNC_ALT1,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_adc_ain1 = { MXC_GPIO0, MXC_GPIO_PIN_12, MXC_GPIO_FUNC_ALT1,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_adc_ain2 = { MXC_GPIO0, MXC_GPIO_PIN_11, MXC_GPIO_FUNC_ALT1,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_adc_ain3 = { MXC_GPIO0, MXC_GPIO_PIN_10, MXC_GPIO_FUNC_ALT1,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };

const mxc_gpio_cfg_t gpio_cfg_adc_trig_p0_9 = { MXC_GPIO0, MXC_GPIO_PIN_9, MXC_GPIO_FUNC_ALT4,
                                                MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_adc_trig_p0_0 = { MXC_GPIO0, MXC_GPIO_PIN_0, MXC_GPIO_FUNC_ALT5,
                                                MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };

const mxc_gpio_cfg_t gpio_cfg_can = { MXC_GPIO0, (MXC_GPIO_PIN_6 | MXC_GPIO_PIN_9),
                                      MXC_GPIO_FUNC_ALT2, MXC_GPIO_PAD_NONE,
                                      MXC_GPIO_VSSEL_VDDIOH };
const mxc_gpio_cfg_t gpio_cfg_canb = { MXC_GPIO0, (MXC_GPIO_PIN_15 | MXC_GPIO_PIN_16),
                                       MXC_GPIO_FUNC_ALT2, MXC_GPIO_PAD_NONE,
                                       MXC_GPIO_VSSEL_VDDIOH };

// SPI v2 Pin Definitions
const mxc_gpio_cfg_t gpio_cfg_spi0_standard = { MXC_GPIO0,
                                                (MXC_GPIO_PIN_2 | MXC_GPIO_PIN_3 | MXC_GPIO_PIN_4),
                                                MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE,
                                                MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi0_3wire = { MXC_GPIO0, (MXC_GPIO_PIN_5 | MXC_GPIO_PIN_6),
                                             MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE,
                                             MXC_GPIO_VSSEL_VDDIO };
// MXC_SPI0 does not support Dual or Quad mode.

const mxc_gpio_cfg_t gpio_cfg_spi1a_standard = {
    MXC_GPIO0, (MXC_GPIO_PIN_7 | MXC_GPIO_PIN_8 | MXC_GPIO_PIN_13), MXC_GPIO_FUNC_ALT1,
    MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO
};
const mxc_gpio_cfg_t gpio_cfg_spi1a_3wire = { MXC_GPIO0, (MXC_GPIO_PIN_8 | MXC_GPIO_PIN_17),
                                              MXC_GPIO_FUNC_ALT1, MXC_GPIO_PAD_NONE,
                                              MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi1b_standard = {
    MXC_GPIO0, (MXC_GPIO_PIN_11 | MXC_GPIO_PIN_12 | MXC_GPIO_PIN_13), MXC_GPIO_FUNC_ALT2,
    MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO
};
const mxc_gpio_cfg_t gpio_cfg_spi1b_3wire = { MXC_GPIO0, (MXC_GPIO_PIN_11 | MXC_GPIO_PIN_12),
                                              MXC_GPIO_FUNC_ALT2, MXC_GPIO_PAD_NONE,
                                              MXC_GPIO_VSSEL_VDDIO };
// MXC_SPI1 does not support Dual or Quad mode.

// SPI v2 Target Selects Pin Definitions
const mxc_gpio_cfg_t gpio_cfg_spi0_ts0 = { MXC_GPIO0, MXC_GPIO_PIN_5, MXC_GPIO_FUNC_ALT1,
                                           MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi1a_ts0 = { MXC_GPIO0, MXC_GPIO_PIN_18, MXC_GPIO_FUNC_ALT1,
                                            MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
const mxc_gpio_cfg_t gpio_cfg_spi1b_ts0 = { MXC_GPIO0, MXC_GPIO_PIN_10, MXC_GPIO_FUNC_ALT2,
                                            MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO };
