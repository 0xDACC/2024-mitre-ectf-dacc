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
 * @brief   Demonstrates a watchdog timer in run mode
 *
 * @details When the program starts LED1 blinks three times and stops.
 *          Then LED0 start blinking continuously.
 *          Open a terminal program to see interrupt messages.
 *
 *          SW0: Push SW0 to configure WDT as reset and interrupt mode, for OVERFLOW mode
 *
 *          SW1: Push SW1 to configure WDT as reset mode, for UNDERFLOW mode
 */

/***** Includes *****/
#include <stdio.h>
#include <stdint.h>
#include "mxc_device.h"
#include "nvic_table.h"
#include "board.h"
#include "mxc_sys.h"
#include "wdt.h"
#include "mxc_delay.h"
#include "led.h"
#include "pb.h"

/***** Definitions *****/

/***** Globals *****/
static mxc_wdt_cfg_t cfg;

#define SW0 0
#define SW1 1

/***** Functions *****/

// *****************************************************************************
void WDT0_IRQHandler(void)
{
    MXC_WDT_ClearIntFlag(MXC_WDT0);
    printf("\nTIMEOUT! \n");
}

// *****************************************************************************
void blinkled(int led, int num_of_blink)
{
    for (int i = 0; i < num_of_blink; i++) {
        LED_On(led);
        MXC_Delay(MXC_DELAY_MSEC(100));
        LED_Off(led);
        MXC_Delay(MXC_DELAY_MSEC(100));
    }
}

// *****************************************************************************
int main(void)
{
    cfg.mode = MXC_WDT_WINDOWED;
    MXC_WDT_Init(MXC_WDT0, &cfg);

    if (MXC_WDT_GetResetFlag(MXC_WDT0)) {
        uint32_t resetFlags = MXC_WDT_GetResetFlag(MXC_WDT0);

        if (resetFlags == MXC_F_WDT_CTRL_RST_LATE) {
            printf("\nWatchdog Reset occured too late (OVERFLOW)\n");
        } else if (resetFlags == MXC_F_WDT_CTRL_RST_EARLY) {
            printf("\nWatchdog Reset occured too soon (UNDERFLOW)\n");
        }

        MXC_WDT_ClearResetFlag(MXC_WDT0);
        MXC_WDT_ClearIntFlag(MXC_WDT0);
    }

    printf("\n************** Watchdog Timer Demo ****************\n");
    printf("Watchdog timer is configured in Windowed mode. You can\n");
    printf("select between two tests: Timer Overflow and Underflow by pressing SW0 and SW1.\n");
    printf("\nPress buttons to create watchdog interrupt and reset:\n");
    printf("Push button 0 = timeout and reset program\n");
    printf("Push button 1 = reset program\n\n");

    //blink LED1 three times at startup
    blinkled(1, 3);

    //Disable watchdog
    MXC_WDT_Disable(MXC_WDT0);
    MXC_WDT_ResetTimer(MXC_WDT0);

    MXC_NVIC_SetVector(WDT0_IRQn, WDT0_IRQHandler);
    NVIC_EnableIRQ(WDT0_IRQn);

    //Push SW1 to start longer delay - shows Interrupt before the reset happens

    while (1) {
        //Push SW1 to reset watchdog
        if (PB_Get(SW0) == TRUE) {
            printf("\nSetting Reset and Interrupt Period...\n");
            MXC_WDT_Disable(MXC_WDT0);
            cfg.upperResetPeriod = MXC_WDT_PERIOD_2_28;
            cfg.upperIntPeriod = MXC_WDT_PERIOD_2_27;
            cfg.lowerResetPeriod = MXC_WDT_PERIOD_2_24;
            cfg.lowerIntPeriod = MXC_WDT_PERIOD_2_23;
            MXC_WDT_SetResetPeriod(MXC_WDT0, &cfg);
            MXC_WDT_SetIntPeriod(MXC_WDT0, &cfg);
            MXC_WDT_ResetTimer(MXC_WDT0);
            MXC_WDT_EnableReset(MXC_WDT0);
            MXC_WDT_EnableInt(MXC_WDT0);

            MXC_WDT_Enable(MXC_WDT0);

            // OVERFLOW Interrupt
            while (1) {
                {
                }
                // wait until interrupt
            }
        }

        if (PB_Get(SW1) == TRUE) {
            printf("\nSetting Reset Period...\n");
            MXC_WDT_Disable(MXC_WDT0);
            cfg.upperResetPeriod = MXC_WDT_PERIOD_2_28;
            cfg.lowerResetPeriod = MXC_WDT_PERIOD_2_24;
            MXC_WDT_SetResetPeriod(MXC_WDT0, &cfg);
            MXC_WDT_ResetTimer(MXC_WDT0);
            MXC_WDT_EnableReset(MXC_WDT0);

            MXC_WDT_Enable(MXC_WDT0);

            // UNDERFLOW Interrupt
        }

        //blink LED0
        blinkled(0, 1);

        //Reset watchdog
        MXC_WDT_ResetTimer(MXC_WDT0);
    }
}
