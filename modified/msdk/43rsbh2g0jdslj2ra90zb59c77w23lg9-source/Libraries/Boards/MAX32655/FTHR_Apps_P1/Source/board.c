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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mxc_device.h"
#include "mxc_sys.h"
#include "mxc_assert.h"
#include "board.h"
#include "uart.h"
#include "gpio.h"
#include "i2c.h"
#include "mxc_pins.h"
#include "led.h"
#include "max20303.h"
#include "pb.h"
#include "spi.h"
#include "Ext_Flash.h"
/***** Global Variables *****/
mxc_uart_regs_t *ConsoleUart = MXC_UART_GET_UART(CONSOLE_UART);
extern uint32_t SystemCoreClock;

const mxc_gpio_cfg_t pb_pin[] = {
    { MXC_GPIO0, MXC_GPIO_PIN_2, MXC_GPIO_FUNC_IN, MXC_GPIO_PAD_PULL_UP, MXC_GPIO_VSSEL_VDDIO },
    { MXC_GPIO0, MXC_GPIO_PIN_3, MXC_GPIO_FUNC_IN, MXC_GPIO_PAD_PULL_UP, MXC_GPIO_VSSEL_VDDIO },
};
const unsigned int num_pbs = (sizeof(pb_pin) / sizeof(mxc_gpio_cfg_t));

const mxc_gpio_cfg_t pb_wakeup_pin[] = {
    { MXC_GPIO3, MXC_GPIO_PIN_1, MXC_GPIO_FUNC_IN, MXC_GPIO_PAD_PULL_UP, MXC_GPIO_VSSEL_VDDIO },
};

const mxc_gpio_cfg_t led_pin[] = {
    { MXC_GPIO0, MXC_GPIO_PIN_18, MXC_GPIO_FUNC_OUT, MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO },
    { MXC_GPIO0, MXC_GPIO_PIN_19, MXC_GPIO_FUNC_OUT, MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO },
    { MXC_GPIO0, MXC_GPIO_PIN_26, MXC_GPIO_FUNC_OUT, MXC_GPIO_PAD_NONE, MXC_GPIO_VSSEL_VDDIO },
};
const unsigned int num_leds = (sizeof(led_pin) / sizeof(mxc_gpio_cfg_t));

/******************************************************************************/
/** 
 * NOTE: This weak definition is included to support Push Button interrupts in
 *       case the user does not define this interrupt handler in their application.
 **/
__weak void GPIO0_IRQHandler(void)
{
    MXC_GPIO_Handler(MXC_GPIO_GET_IDX(MXC_GPIO0));
}

#ifndef __riscv /* RISCV does not have access to MXC_SPI0 */

/******************************************************************************/
static void ext_flash_board_init_quad(bool quadEnabled)
{
    mxc_gpio_cfg_t sdio23;

    sdio23.port = MXC_GPIO0;
    sdio23.mask = (MXC_GPIO_PIN_8 | MXC_GPIO_PIN_9);
    sdio23.pad = MXC_GPIO_PAD_NONE;
    sdio23.vssel = MXC_GPIO_VSSEL_VDDIOH;

    if (quadEnabled) {
        /* Enable these pins as SPI SDIO2/3*/
        sdio23.func = MXC_GPIO_FUNC_ALT1;
        MXC_GPIO_Config(&sdio23);

    } else {
        /* Control these pins as GPIO and set high when not using quad mode.
         * The W25 used on this board multiplexes the HOLD and WP functions on these
         * pins when not using quad mode
         */
        sdio23.func = MXC_GPIO_FUNC_OUT;
        MXC_GPIO_Config(&sdio23);
        MXC_GPIO_OutSet(sdio23.port, sdio23.mask);
    }
}

/******************************************************************************/
static int ext_flash_board_init(void)
{
    mxc_spi_pins_t qspi_flash_pins;
    int err = E_NO_ERROR;

    qspi_flash_pins.clock = true;
    qspi_flash_pins.ss0 = true;
    qspi_flash_pins.ss1 = true;
    qspi_flash_pins.ss2 = false;
    qspi_flash_pins.miso = true;
    qspi_flash_pins.mosi = true;
    qspi_flash_pins.vddioh = true;

    err = MXC_SPI_Init(MXC_SPI0, 1, 1, 1, 0, EXT_FLASH_BAUD, qspi_flash_pins);
    if (err != E_NO_ERROR) {
        return err;
    }

    MXC_SPI_SetDataSize(MXC_SPI0, 8);
    MXC_SPI_SetMode(MXC_SPI0, SPI_MODE_0);

    /* Leave the quad pins disabled, enable for quad transactions. */
    ext_flash_board_init_quad(false);

    return err;
}

/******************************************************************************/
static int ext_flash_board_read(uint8_t *read, unsigned len, unsigned deassert,
                                Ext_Flash_DataLine_t width)
{
    mxc_spi_req_t qspi_read_req;
    mxc_spi_width_t spi_width;
    int err = E_NO_ERROR;

    switch (width) {
    case Ext_Flash_DataLine_Single:
        spi_width = SPI_WIDTH_STANDARD;
        break;
    case Ext_Flash_DataLine_Dual:
        spi_width = SPI_WIDTH_DUAL;
        break;
    case Ext_Flash_DataLine_Quad:
        spi_width = SPI_WIDTH_QUAD;
        ext_flash_board_init_quad(true);
        break;
    default:
        return E_BAD_PARAM;
    }

    MXC_SPI_SetWidth(MXC_SPI0, spi_width);

    qspi_read_req.spi = MXC_SPI0;
    qspi_read_req.ssIdx = 1;
    qspi_read_req.ssDeassert = deassert;
    qspi_read_req.txData = NULL;
    qspi_read_req.rxData = read;
    qspi_read_req.txLen = 0;
    qspi_read_req.rxLen = len;
    qspi_read_req.txCnt = 0;
    qspi_read_req.rxCnt = 0;
    qspi_read_req.completeCB = NULL;

    err = MXC_SPI_MasterTransaction(&qspi_read_req);
    if (err != E_NO_ERROR) {
        if (width == Ext_Flash_DataLine_Quad) {
            /* Restore the SPI config to disable quad pins */
            ext_flash_board_init_quad(false);
        }
        return err;
    }

    if (width == Ext_Flash_DataLine_Quad) {
        /* Restore the SPI config to disable quad pins */
        ext_flash_board_init_quad(false);
    }

    return err;
}

/******************************************************************************/
static int ext_flash_board_write(const uint8_t *write, unsigned len, unsigned deassert,
                                 Ext_Flash_DataLine_t width)
{
    mxc_spi_req_t qspi_write_req;
    mxc_spi_width_t spi_width;
    int err = E_NO_ERROR;

    switch (width) {
    case Ext_Flash_DataLine_Single:
        spi_width = SPI_WIDTH_STANDARD;
        break;
    case Ext_Flash_DataLine_Dual:
        spi_width = SPI_WIDTH_DUAL;
        break;
    case Ext_Flash_DataLine_Quad:
        spi_width = SPI_WIDTH_QUAD;
        ext_flash_board_init_quad(true);
        break;
    default:
        return E_BAD_PARAM;
    }

    MXC_SPI_SetWidth(MXC_SPI0, spi_width);

    qspi_write_req.spi = MXC_SPI0;
    qspi_write_req.ssIdx = 1;
    qspi_write_req.ssDeassert = deassert;
    qspi_write_req.txData = (uint8_t *)write;
    qspi_write_req.rxData = NULL;
    qspi_write_req.txLen = len;
    qspi_write_req.rxLen = 0;
    qspi_write_req.txCnt = 0;
    qspi_write_req.rxCnt = 0;
    qspi_write_req.completeCB = NULL;

    err = MXC_SPI_MasterTransaction(&qspi_write_req);
    if (err != E_NO_ERROR) {
        if (width == Ext_Flash_DataLine_Quad) {
            /* Restore the SPI config to disable quad pins */
            ext_flash_board_init_quad(false);
        }
        return err;
    }

    if (width == Ext_Flash_DataLine_Quad) {
        /* Restore the SPI config to disable quad pins */
        ext_flash_board_init_quad(false);
    }

    return err;
}

/******************************************************************************/
static int ext_flash_clock(unsigned len, unsigned deassert)
{
    mxc_spi_req_t qspi_dummy_req;
    mxc_spi_width_t width;
    uint8_t *write;
    int res;

    if (MXC_SPI_GetDataSize(MXC_SPI0) != 8) {
        return E_BAD_STATE;
    }

    width = MXC_SPI_GetWidth(MXC_SPI0);

    switch (width) {
    case SPI_WIDTH_STANDARD:
        len /= 8;
        break;
    case SPI_WIDTH_DUAL:
        len /= 4;
        break;
    case SPI_WIDTH_QUAD:
        len /= 2;
        break;
    default:
        return E_BAD_STATE;
    }

    write = (uint8_t *)malloc(len);
    memset(write, 0, len);

    qspi_dummy_req.spi = MXC_SPI0;
    qspi_dummy_req.ssIdx = 1;
    qspi_dummy_req.ssDeassert = deassert;
    qspi_dummy_req.txData = write;
    qspi_dummy_req.rxData = NULL;
    qspi_dummy_req.txLen = len;
    qspi_dummy_req.rxLen = 0;
    qspi_dummy_req.txCnt = 0;
    qspi_dummy_req.rxCnt = 0;
    qspi_dummy_req.completeCB = NULL;

    res = MXC_SPI_MasterTransaction(&qspi_dummy_req);
    free(write);
    return res;
}
#endif /* __riscv */
/******************************************************************************/
void mxc_assert(const char *expr, const char *file, int line)
{
#ifdef DEBUG
    printf("MXC_ASSERT %s #%d: (%s)\n", file, line, expr);
#endif
    while (1) {}
}

/******************************************************************************/
/*
void SystemCoreClockUpdate(void)
{
    SystemCoreClock = RO_FREQ;
}
*/
/******************************************************************************/
int Board_Init(void)
{
    int err;

#ifndef __riscv /* RISCV does not have access to MXC_SPI0 */
    Ext_Flash_Config_t exf_cfg = { .init = ext_flash_board_init,
                                   .read = ext_flash_board_read,
                                   .write = ext_flash_board_write,
                                   .clock = ext_flash_clock };

    if ((err = Ext_Flash_Configure(&exf_cfg)) != E_NO_ERROR) {
        return err;
    }
#endif // __riscv

    // Enable GPIO
    MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_GPIO0);
    MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_GPIO1);
    MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_GPIO2);

#ifdef DEBUG
    if ((err = Console_Init()) < E_NO_ERROR) {
        return err;
    }
#endif

    if ((err = PB_Init()) != E_NO_ERROR) {
        MXC_ASSERT_FAIL();
        return err;
    }

    if ((err = LED_Init()) != E_NO_ERROR) {
        MXC_ASSERT_FAIL();
        return err;
    }

    return E_NO_ERROR;
}

/******************************************************************************/
int Console_Init(void)
{
    int err;

    if ((err = MXC_UART_Init(ConsoleUart, CONSOLE_BAUD, MXC_UART_IBRO_CLK)) != E_NO_ERROR) {
        return err;
    }

    return E_NO_ERROR;
}

/******************************************************************************/
int Console_Shutdown(void)
{
    int err;

    if ((err = MXC_UART_Shutdown(ConsoleUart)) != E_NO_ERROR) {
        return err;
    }

    return E_NO_ERROR;
}

/******************************************************************************/
int Console_PrepForSleep(void)
{
    return MXC_UART_ReadyForSleep(ConsoleUart);
}

/******************************************************************************/
void GPIO_PrepForSleep(void)
{
    /* TODO: Setup the unused GPIO high */
}

/******************************************************************************/
void NMI_Handler(void)
{
    __NOP();
}

#ifdef __riscv
/******************************************************************************/
int Debug_Init(void)
{
    // Set up RISCV JTAG pins (P1[0..3] AF2)
    MXC_GPIO1->en0_clr = 0x0f;
    MXC_GPIO1->en1_set = 0x0f;
    MXC_GPIO1->en2_clr = 0x0f;

    return E_NO_ERROR;
}
#endif // __riscv

/******************************************************************************/
int Camera_Power(int on)
{
    int err;

    if ((err = max20303_init(MAX20303_I2C)) != E_NO_ERROR) {
        return err;
    }

    return max20303_camera_power(on);
}

/******************************************************************************/
int Microphone_Power(int on)
{
    int err;

    if ((err = max20303_init(MAX20303_I2C)) != E_NO_ERROR) {
        return err;
    }

    return max20303_mic_power(on);
}
