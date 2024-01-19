/*******************************************************************************
* Copyright (C) Maxim Integrated Products, Inc., All Rights Reserved.
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
 * @details When the program starts LED3 blinks three times and stops.
 *          Then LED0 start blinking continuously.
 *          Open a terminal program to see interrupt messages.
 *
 *          SW2: Push SW2 to trigger a watchdog reset. This will reset the watchdog before
 *               the wait period has expired and trigger an interrupt.
 *
 *          SW3: Push SW3 to trigger a delay and see LED0 stop blinking momentarily.
 *               This delay long enough for the timeout period to expire and trigger an interrupt.
 *
 *          SW3: Push SW3 to trigger a longer delay and see the program restart by blinking LED3 three times.
 *               This delay is long enough for the reset period to expire and trigger a reset.
 */

/***** Includes *****/
#include <stdio.h>
#include <stdint.h>

#include <MAX32xxx.h>

/***** Definitions *****/
/***** Globals *****/
//use push buttons defined in board.h
extern const mxc_gpio_cfg_t pb_pin[];
extern const mxc_gpio_cfg_t led_pin[];

// refers to array, do not change constants
#define SW1 0
#define LED 0
/***** Functions *****/

// *****************************************************************************
void watchdogHandler()
{
    //get and clear flag
    MXC_WDT_GetIntFlag(MXC_WDT0);
    MXC_WDT_ClearIntFlag(MXC_WDT0);
    printf("TIMEOUT! \n");
}

// *****************************************************************************
void WDT0_IRQHandler(void)
{
    watchdogHandler();
}
// *****************************************************************************
void MXC_WDT_Setup()
{
    MXC_WDT_Disable(MXC_WDT0);
    MXC_WDT_Enable(MXC_WDT0);
}

// *****************************************************************************
int main(void)
{
    MXC_WDT_Init(MXC_WDT0);

    if (MXC_WDT_GetResetFlag(MXC_WDT0)) {
        MXC_WDT_ClearResetFlag(MXC_WDT0);
        MXC_WDT_EnableReset(MXC_WDT0);
        MXC_WDT_Enable(MXC_WDT0);
        printf("Watchdog reset\n");
    }

    printf("\n************** Watchdog Timer Demo ****************\n");
    printf("Press a button to create watchdog interrupt or reset:\n");
    printf("SW2 (P0.16)= reset program\n");
    printf("SW3 (P0.17)= timeout interrupt\n\n");

    //Blink LED
    MXC_GPIO_OutClr(led_pin[0].port, led_pin[0].mask);

    //Blink LED three times at startup
    int numBlinks = 3;

    while (numBlinks) {
        MXC_GPIO_OutSet(led_pin[0].port, led_pin[0].mask);
        MXC_Delay(MXC_DELAY_MSEC(100));
        MXC_GPIO_OutClr(led_pin[0].port, led_pin[0].mask);
        MXC_Delay(MXC_DELAY_MSEC(100));
        numBlinks--;
    }

    //Setup watchdog
    MXC_WDT_Setup();

    while (1) {
        //Push SW1 to reset watchdog
        if (MXC_GPIO_InGet(pb_pin[SW1].port, pb_pin[SW1].mask) == 0) {
            printf("Enabling Timeout Interrupt...\n");
            MXC_WDT_SetResetPeriod(MXC_WDT0, MXC_WDT_PERIOD_2_27);
            MXC_WDT_SetIntPeriod(MXC_WDT0, MXC_WDT_PERIOD_2_26);
            MXC_WDT_EnableReset(MXC_WDT0);
            MXC_WDT_EnableInt(MXC_WDT0);
            NVIC_EnableIRQ(WDT0_IRQn);

            while (1) {}
        }

        //blink LED0
        MXC_Delay(MXC_DELAY_MSEC(500));
        MXC_GPIO_OutSet(led_pin[0].port, led_pin[0].mask);
        MXC_Delay(MXC_DELAY_MSEC(500));
        MXC_GPIO_OutClr(led_pin[0].port, led_pin[0].mask);

        //Reset watchdog
        MXC_WDT_ResetTimer(MXC_WDT0);
    }
}
