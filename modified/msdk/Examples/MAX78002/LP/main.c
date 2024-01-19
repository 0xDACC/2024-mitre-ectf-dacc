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

/*
 * @file    main.c
 * @brief   Demonstrates the various low power modes.
 *
 * @details Iterates through the various low power modes, using either the RTC
 *          alarm or a GPIO to wake from each.  #defines determine which wakeup
 *          source to use.  Once the code is running, you can measure the
 *          current used on the VCORE rail.
 *
 *          The power states shown are (depending on the enabled mode):
 *            1. Active mode power with all clocks
 *            2. Active mode power with peripheral clocks disabled (if USE_CONSOLE is 0)
 *            3. SLEEP mode
 *            4. LPM mode
 *            5. UPM mode
 *            6. STANDBY mode
 *            7. BACKUP mode
 *            8. Power Down mode

 */

#include <stdio.h>
#include <stdint.h>

#include "icc.h"
#include "led.h"
#include "lp.h"
#include "mxc_delay.h"
#include "mxc_device.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include "pb.h"
#include "rtc.h"
#include "uart.h"

#define DELAY_IN_SEC 4
#define USE_CONSOLE 1

#define USE_BUTTON 1
#define USE_ALARM 0

#define DISABLE_GPIO 0 // it configures all GPIOs as input to save power

#define DO_SLEEP 1
#define DO_LPM 1
#define DO_UPM 0
#define DO_STANDBY 1
#define DO_BACKUP 1 // will reset after waking up
#define DO_POWERDOWN 0 // will reset after waking up

#if (!(USE_BUTTON || USE_ALARM))
#error "You must set either USE_BUTTON or USE_ALARM to 1."
#endif
#if (USE_BUTTON && USE_ALARM)
#error "You must select either USE_BUTTON or USE_ALARM, not both."
#endif

#if (DO_BACKUP && DO_POWERDOWN)
#error "You must select either DO_BACKUP or DO_POWERDOWN or neither, not both."
#endif

#if USE_CONSOLE
#define PRINT(...) printf(__VA_ARGS__)
#else
#define PRINT(...)
#endif

// *****************************************************************************

#if USE_ALARM
volatile int alarmed;
void alarmHandler(void)
{
    int flags = MXC_RTC->ctrl;
    alarmed = 1;

    if ((flags & MXC_F_RTC_CTRL_SSEC_ALARM) >> MXC_F_RTC_CTRL_SSEC_ALARM_POS) {
        MXC_RTC->ctrl &= ~(MXC_F_RTC_CTRL_SSEC_ALARM);
    }

    if ((flags & MXC_F_RTC_CTRL_TOD_ALARM) >> MXC_F_RTC_CTRL_TOD_ALARM_POS) {
        MXC_RTC->ctrl &= ~(MXC_F_RTC_CTRL_TOD_ALARM);
    }
}

void setTrigger(int waitForTrigger)
{
    alarmed = 0;

    while (MXC_RTC_Init(0, 0) == E_BUSY) {}

    while (MXC_RTC_DisableInt(MXC_F_RTC_CTRL_TOD_ALARM_IE) == E_BUSY) {}

    while (MXC_RTC_SetTimeofdayAlarm(DELAY_IN_SEC) == E_BUSY) {}

    while (MXC_RTC_EnableInt(MXC_F_RTC_CTRL_TOD_ALARM_IE) == E_BUSY) {}

    while (MXC_RTC_Start() == E_BUSY) {}

    if (waitForTrigger) {
        while (!alarmed) {}
    }

    // Wait for serial transactions to complete.
#if USE_CONSOLE

    while (MXC_UART_ReadyForSleep(MXC_UART_GET_UART(CONSOLE_UART)) != E_NO_ERROR) {}

#endif // USE_CONSOLE
}
#endif // USE_ALARM

#if USE_BUTTON
volatile int buttonPressed;
void buttonHandler(void *pb)
{
    buttonPressed = 1;
}

void setTrigger(int waitForTrigger)
{
    int tmp;

    buttonPressed = 0;

    if (waitForTrigger) {
        while (!buttonPressed) {}
    }

    // Debounce the button press.
    for (tmp = 0; tmp < 0x240000; tmp++) {
        __NOP();
    }

    // Wait for serial transactions to complete.
#if USE_CONSOLE

    while (MXC_UART_ReadyForSleep(MXC_UART_GET_UART(CONSOLE_UART)) != E_NO_ERROR) {}

#endif // USE_CONSOLE
}
#endif // USE_BUTTON

int main(void)
{
    PRINT("****Low Power Mode Example****\n\n");

#if USE_ALARM
    PRINT("This code cycles through the MAX78002 power modes, using the RTC alarm to exit from "
          "each mode.  The modes will change every %d seconds.\n\n",
          DELAY_IN_SEC);
#if !DISABLE_GPIO
    PRINT("Set the EvKit power monitor display to System Power Mode to measure the power in each "
          "mode.\n\n");
#endif
    MXC_NVIC_SetVector(RTC_IRQn, alarmHandler);
#endif // USE_ALARM

#if USE_BUTTON
    PRINT("This code cycles through the MAX78002 power modes, using a push button (PB1) to exit "
          "from each mode and enter the next.\n\n");
    PB_RegisterCallback(0, buttonHandler);
#endif // USE_BUTTON

    // Configure trig1 for system power measurement
    mxc_gpio_cfg_t gpio_trig1;
    gpio_trig1.port = MXC_GPIO1;
    gpio_trig1.mask = MXC_GPIO_PIN_6;
    gpio_trig1.pad = MXC_GPIO_PAD_NONE;
    gpio_trig1.func = MXC_GPIO_FUNC_OUT;
    MXC_GPIO_Config(&gpio_trig1);

#if DISABLE_GPIO
    // To save power, configure all GPIOs as input, only keep console (or LEDs)
    mxc_gpio_cfg_t gpios_in;

    // all GPIOs input with pullup
    gpios_in.pad = MXC_GPIO_PAD_PULL_UP;
    gpios_in.func = MXC_GPIO_FUNC_IN;
    gpios_in.vssel = MXC_GPIO_VSSEL_VDDIO;

    // PORT3 input
    gpios_in.port = MXC_GPIO3;
    gpios_in.mask = 0xFFFFFFFF;
    MXC_GPIO_Config(&gpios_in);

    // PORT2 input
    gpios_in.port = MXC_GPIO2;
    MXC_GPIO_Config(&gpios_in);

    // PORT1 input
    gpios_in.port = MXC_GPIO1;
    MXC_GPIO_Config(&gpios_in);

    // PORT0 input except consule
    gpios_in.port = MXC_GPIO0;
    gpios_in.mask = 0xFFFFFFFD; // except UART0-TX for debug
    MXC_GPIO_Config(&gpios_in);

#endif

    PRINT("Running in ACTIVE mode.\n");
#if !USE_CONSOLE
    MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_UART0);
#endif // USE_CONSOLE
    MXC_GPIO_OutSet(gpio_trig1.port, gpio_trig1.mask);
    setTrigger(1);
    MXC_GPIO_OutClr(gpio_trig1.port, gpio_trig1.mask);

#if USE_BUTTON
    MXC_LP_EnableGPIOWakeup((mxc_gpio_cfg_t *)&pb_pin[0]);
    MXC_GPIO_SetWakeEn(pb_pin[0].port, pb_pin[0].mask);
#endif // USE_BUTTON
#if USE_ALARM
    MXC_LP_EnableRTCAlarmWakeup();
#endif // USE_ALARM

    while (1) {
#if DO_SLEEP
        PRINT("Entering SLEEP mode.\n");
        setTrigger(0);
        MXC_GPIO_OutSet(gpio_trig1.port, gpio_trig1.mask);
        MXC_LP_EnterSleepMode();
        MXC_GPIO_OutClr(gpio_trig1.port, gpio_trig1.mask);
        PRINT("Waking up from SLEEP mode.\n");
#endif // DO_SLEEP

#if DO_LPM
        PRINT("Entering Low power mode.\n");
        setTrigger(0);
        MXC_GPIO_OutSet(gpio_trig1.port, gpio_trig1.mask);
        MXC_LP_EnterLowPowerMode();
        MXC_GPIO_OutClr(gpio_trig1.port, gpio_trig1.mask);
        PRINT("Waking up from Low power mode.\n");
#endif // DO_LPM

#if DO_UPM
        PRINT("Entering Micro power mode.\n");
        setTrigger(0);
        MXC_GPIO_OutSet(gpio_trig1.port, gpio_trig1.mask);
        MXC_LP_EnterMicroPowerMode();
        MXC_GPIO_OutClr(gpio_trig1.port, gpio_trig1.mask);
        PRINT("Waking up from Micro power mode.\n");
#endif // DO_UPM

#if DO_STANDBY
        PRINT("Entering STANDBY mode.\n");
        setTrigger(0);
        MXC_GPIO_OutSet(gpio_trig1.port, gpio_trig1.mask);
        MXC_LP_EnterStandbyMode();
        MXC_GPIO_OutClr(gpio_trig1.port, gpio_trig1.mask);
        PRINT("Waking up from STANDBY mode.\n");
#endif // DO_STANDBY

#if DO_BACKUP
        PRINT("Entering BACKUP mode.\n");
        setTrigger(0);
        MXC_GPIO_OutSet(gpio_trig1.port, gpio_trig1.mask);
        MXC_LP_EnterBackupMode();
#endif // DO_BACKUP

#if DO_POWERDOWN
        PRINT("Entering Power Down mode, press reset or P3.0/1 = 0 to restart.\n");
        setTrigger(0);

        mxc_gpio_cfg_t gpio_in;

        // The two GPIO3 pins are pulled down to 0 by default due to internal weak pulldown.
        // As soon as you enter PDM mode, the pin becomes a weak pull-up and causes an immidiate wakeup condition.
        // To avoid, configure P3.0 as input with pullup for PDM to work properly
        gpio_in.port = MXC_GPIO3;
        gpio_in.pad = MXC_GPIO_PAD_PULL_UP;
        gpio_in.func = MXC_GPIO_FUNC_IN;
        gpio_in.vssel = MXC_GPIO_VSSEL_VDDIOH;

        gpio_in.mask = MXC_GPIO_PIN_0;
        MXC_GPIO_Config(&gpio_in);

        MXC_GPIO_OutSet(gpio_trig1.port, gpio_trig1.mask);
        MXC_LP_EnterPowerDownMode();
#endif // DO_POWERDOWN
    }
}
