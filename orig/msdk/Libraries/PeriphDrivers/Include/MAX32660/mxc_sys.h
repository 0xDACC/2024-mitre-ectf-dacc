/**
 * @file    mxc_sys.h
 * @brief   System level header file.
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

#ifndef LIBRARIES_PERIPHDRIVERS_INCLUDE_MAX32660_MXC_SYS_H_
#define LIBRARIES_PERIPHDRIVERS_INCLUDE_MAX32660_MXC_SYS_H_

#include "mxc_device.h"
#include "gcr_regs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup mxc_sys System Configuration (MXC_SYS)
 * @ingroup syscfg
 * @details API for system configuration including clock source selection and entering critical sections of code.
 * @{
 */

/** @brief System reset0 and reset1 enumeration. Used in MXC_SYS_PeriphReset0 function */
typedef enum {
    MXC_SYS_RESET0_DMA = MXC_F_GCR_RST0_DMA_POS, /**< Reset DMA */
    MXC_SYS_RESET0_WDT0 = MXC_F_GCR_RST0_WDT0_POS, /**< Reset WDT */
    MXC_SYS_RESET0_GPIO0 = MXC_F_GCR_RST0_GPIO0_POS, /**< Reset GPIO0 */
    MXC_SYS_RESET0_TIMER0 = MXC_F_GCR_RST0_TIMER0_POS, /**< Reset TIMER0 */
    MXC_SYS_RESET0_TIMER1 = MXC_F_GCR_RST0_TIMER1_POS, /**< Reset TIMER1 */
    MXC_SYS_RESET0_TIMER2 = MXC_F_GCR_RST0_TIMER2_POS, /**< Reset TIMER2 */
    MXC_SYS_RESET0_UART0 = MXC_F_GCR_RST0_UART0_POS, /**< Reset UART0 */
    MXC_SYS_RESET0_UART1 = MXC_F_GCR_RST0_UART1_POS, /**< Reset UART1 */
    MXC_SYS_RESET0_SPI0 = MXC_F_GCR_RST0_SPI0_POS, /**< Reset SPI0 */
    MXC_SYS_RESET0_SPI1 = MXC_F_GCR_RST0_SPI1_POS, /**< Reset SPI1 */
    MXC_SYS_RESET0_I2C0 = MXC_F_GCR_RST0_I2C0_POS, /**< Reset I2C0 */
    MXC_SYS_RESET0_RTC = MXC_F_GCR_RST0_RTC_POS, /**< Reset RTC */
    MXC_SYS_RESET0_SRST = MXC_F_GCR_RST0_SOFT_POS, /**< Soft reset */
    MXC_SYS_RESET0_PRST = MXC_F_GCR_RST0_PERIPH_POS, /**< Peripheral reset */
    MXC_SYS_RESET0_SYSTEM = MXC_F_GCR_RST0_SYSTEM_POS, /**< System reset */
    /* RESET1 Below this line we add 32 to separate RESET0 and RESET1 */
    MXC_SYS_RESET1_I2C1 = (MXC_F_GCR_RST1_I2C1_POS + 32), /**< Reset I2C1 */
} mxc_sys_reset_t;

/** @brief System clock disable enumeration. Used in MXC_SYS_ClockDisable and MXC_SYS_ClockEnable functions */
typedef enum {
    MXC_SYS_PERIPH_CLOCK_GPIO0 =
        MXC_F_GCR_PCLK_DIS0_GPIO0D_POS, /**< Disable MXC_F_GCR_PCLKDIS0_GPIO0 clock */
    MXC_SYS_PERIPH_CLOCK_DMA =
        MXC_F_GCR_PCLK_DIS0_DMAD_POS, /**< Disable MXC_F_GCR_PCLKDIS0_DMA clock */
    MXC_SYS_PERIPH_CLOCK_SPI0 =
        MXC_F_GCR_PCLK_DIS0_SPI0D_POS, /**< Disable MXC_F_GCR_PCLKDIS0_SPI0 clock */
    MXC_SYS_PERIPH_CLOCK_SPI1 =
        MXC_F_GCR_PCLK_DIS0_SPI1D_POS, /**< Disable MXC_F_GCR_PCLKDIS0_SPI1 clock */
    MXC_SYS_PERIPH_CLOCK_UART0 =
        MXC_F_GCR_PCLK_DIS0_UART0D_POS, /**< Disable MXC_F_GCR_PCLKDIS0_UART0 clock */
    MXC_SYS_PERIPH_CLOCK_UART1 =
        MXC_F_GCR_PCLK_DIS0_UART1D_POS, /**< Disable MXC_F_GCR_PCLKDIS0_UART1 clock */
    MXC_SYS_PERIPH_CLOCK_I2C0 =
        MXC_F_GCR_PCLK_DIS0_I2C0D_POS, /**< Disable MXC_F_GCR_PCLKDIS0_I2C0 clock */
    MXC_SYS_PERIPH_CLOCK_TMR0 =
        MXC_F_GCR_PCLK_DIS0_TIMER0D_POS, /**< Disable MXC_F_GCR_PCLKDIS0_T0 clock */
    MXC_SYS_PERIPH_CLOCK_TMR1 =
        MXC_F_GCR_PCLK_DIS0_TIMER1D_POS, /**< Disable MXC_F_GCR_PCLKDIS0_T1 clock */
    MXC_SYS_PERIPH_CLOCK_TMR2 =
        MXC_F_GCR_PCLK_DIS0_TIMER2D_POS, /**< Disable MXC_F_GCR_PCLKDIS0_T2 clock */
    MXC_SYS_PERIPH_CLOCK_I2C1 =
        MXC_F_GCR_PCLK_DIS0_I2C1D_POS, /**< Disable MXC_F_GCR_PCLKDIS0_I2C1 clock */
    /* PCLKDIS1 Below this line we add 32 to separate PCLKDIS0 and PCLKDIS1 */
    MXC_SYS_PERIPH_CLOCK_FLCD =
        (MXC_F_GCR_PCLK_DIS1_FLCD_POS + 32), /**< Disable MXC_F_GCR_PCLKDIS1_WDT1 clock */
    MXC_SYS_PERIPH_CLOCK_ICACHE =
        (MXC_F_GCR_PCLK_DIS1_ICCD_POS + 32), /**< Disable MXC_F_GCR_PCLKDIS1_I2S clock */
} mxc_sys_periph_clock_t;

/** @brief Enumeration to select System Clock source */
typedef enum {
    MXC_SYS_CLOCK_NANORING = MXC_V_GCR_CLK_CTRL_CLKSEL_NANORING, /**< 8KHz nanoring on MAX32660 */
    MXC_SYS_CLOCK_HFXIN = MXC_V_GCR_CLK_CTRL_CLKSEL_HFXIN, /**< 32KHz on MAX32660 */
    MXC_SYS_CLOCK_HFXIN_DIGITAL = 0x9, /**< External Clock Input*/
    MXC_SYS_CLOCK_HIRC = MXC_V_GCR_CLK_CTRL_CLKSEL_HIRC, /**< High Frequency Internal Oscillator */
} mxc_sys_system_clock_t;

#define MXC_SYS_USN_LEN 8

/***** Function Prototypes *****/

typedef struct {
    int ie_status;
    int in_critical;
} mxc_crit_state_t;

static mxc_crit_state_t _state = { .ie_status = (int)0xFFFFFFFF, .in_critical = 0 };

static inline void _mxc_crit_get_state()
{
#ifndef __riscv
    /*
        On ARM M the 0th bit of the Priority Mask register indicates
        whether interrupts are enabled or not.

        0 = enabled
        1 = disabled
    */
    uint32_t primask = __get_PRIMASK();
    _state.ie_status = (primask == 0);
#else
    /*
        On RISC-V bit position 3 (Machine Interrupt Enable) of the
        mstatus register indicates whether interrupts are enabled.

        0 = disabled
        1 = enabled
    */
    uint32_t mstatus = get_mstatus();
    _state.ie_status = ((mstatus & (1 << 3)) != 0);
#endif
}

/**
 * @brief Enter a critical section of code that cannot be interrupted.  Call @ref MXC_SYS_Crit_Exit to exit the critical section.
 * @details Ex:
 * @code
 * MXC_SYS_Crit_Enter();
 * printf("Hello critical section!\n");
 * MXC_SYS_Crit_Exit();
 * @endcode
 * The @ref MXC_CRITICAL macro is also provided as a convencience macro for wrapping a code section in this way.
 * @returns None
 */
static inline void MXC_SYS_Crit_Enter(void)
{
    _mxc_crit_get_state();
    if (_state.ie_status)
        __disable_irq();
    _state.in_critical = 1;
}

/**
 * @brief Exit a critical section of code from @ref MXC_SYS_Crit_Enter
 * @returns None
 */
static inline void MXC_SYS_Crit_Exit(void)
{
    if (_state.ie_status) {
        __enable_irq();
    }
    _state.in_critical = 0;
    _mxc_crit_get_state();
    /*
        ^ Reset the state again to prevent edge case
        where interrupts get disabled, then Crit_Exit() gets
        called, which would inadvertently re-enable interrupts
        from old state.
    */
}

/**
 * @brief Polls whether code is currently executing from a critical section.
 * @returns 1 if code is currently in a critical section (interrupts are disabled).
 *          0 if code is not in a critical section.
 */
static inline int MXC_SYS_In_Crit_Section(void)
{
    return _state.in_critical;
}

// clang-format off
/**
 * @brief Macro for wrapping a section of code to make it critical (interrupts disabled).  Note: this macro
 * does not support nesting.
 * @details
 * Ex:
 * \code
 * MXC_CRITICAL(
 *      printf("Hello critical section!\n");
 * )
 * \endcode
 * This macro places a call to @ref MXC_SYS_Crit_Enter before the code, and a call to @ref MXC_SYS_Crit_Exit after.
 * @param code The code section to wrap.
 */
#define MXC_CRITICAL(code) {\
    MXC_SYS_Crit_Enter();\
    code;\
    MXC_SYS_Crit_Exit();\
}
// clang-format on

/**
 * @brief Reads the device USN.
 * @param usn     Pointer to store the USN.
 * @param len     Length of the USN buffer
 * @param part    Which USN part you want (0, 1, 2)
 * @returns       E_NO_ERROR if everything is successful.
 */
int MXC_SYS_GetUSN(uint8_t *usn, int len, int part);

/**
 * @brief Determines if the selected peripheral clock is enabled.
 * @param clock   Enumeration for desired clock.
 * @returns       0 is the clock is disabled, non 0 if the clock is enabled.
 */
int MXC_SYS_IsClockEnabled(mxc_sys_periph_clock_t clock);

/**
 * @brief Disables the selected peripheral clock.
 * @param clock   Enumeration for desired clock.
 */
void MXC_SYS_ClockDisable(mxc_sys_periph_clock_t clock);

/**
 * @brief Enables the selected peripheral clock.
 * @param clock   Enumeration for desired clock.
 */
void MXC_SYS_ClockEnable(mxc_sys_periph_clock_t clock);

/**
 * @brief Enables the 32kHz oscillator
 * @param mxc_sys_cfg   Not used, may be NULL.
 */
void MXC_SYS_RTCClockEnable(void);

/**
 * @brief Disables the 32kHz oscillator
 * @returns         E_NO_ERROR if everything is successful
 */
int MXC_SYS_RTCClockDisable();

/**
 * @brief Enable System Clock Source without switching to it
 * @param      clock The clock to enable
 * @return     E_NO_ERROR if everything is successful
 */
int MXC_SYS_ClockSourceEnable(mxc_sys_system_clock_t clock);

/**
 * @brief Disable System Clock Source
 * @param      clock The clock to disable
 * @return     E_NO_ERROR if everything is successful
 */
int MXC_SYS_ClockSourceDisable(mxc_sys_system_clock_t clock);

/**
 * @brief Select the system clock.
 * @param clock     Enumeration for desired clock.
 * @returns         E_NO_ERROR if everything is successful.
 */
int MXC_SYS_Clock_Select(mxc_sys_system_clock_t clock);

/**
 * @brief Wait for a clock to enable with timeout
 * @param      ready The clock to wait for
 * @return     E_NO_ERROR if ready, E_TIME_OUT if timeout
 */
int MXC_SYS_Clock_Timeout(uint32_t ready);
/**
 * @brief Reset the peripherals and/or CPU in the rstr0 or rstr1 register.
 * @param           Enumeration for what to reset. Can reset multiple items at once.
 */
void MXC_SYS_Reset_Periph(mxc_sys_reset_t reset);

#ifdef __cplusplus
}
#endif

#endif // LIBRARIES_PERIPHDRIVERS_INCLUDE_MAX32660_MXC_SYS_H_
