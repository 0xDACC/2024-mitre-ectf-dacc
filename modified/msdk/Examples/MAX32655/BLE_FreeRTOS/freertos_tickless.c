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

/* Maxim CMSIS */
#include "mxc_device.h"
#include "board.h"
#include "mxc_assert.h"
#include "lp.h"
#include "pwrseq_regs.h"
#include "wut.h"
#include "mcr_regs.h"
#include "icc.h"
#include "pb.h"
#include "led.h"
#include "uart.h"

/* FreeRTOS includes */
#include "FreeRTOS.h"
#include "FreeRTOSConfig.h"
#include "task.h"

/* Bluetooth Cordio library */
#include "pal_timer.h"
#include "pal_uart.h"
#include "pal_bb.h"

#define MAX_WUT_TICKS (configRTC_TICK_RATE_HZ) /* Maximum deep sleep time, units of 32 kHz ticks */
#define MIN_WUT_TICKS 100 /* Minimum deep sleep time, units of 32 kHz ticks */
#define WAKEUP_US 700 /* Deep sleep recovery time, units of us */

/* Minimum ticks before SysTick interrupt, units of system clock ticks.
 * Convert CPU_CLOCK_HZ to units of ticks per us 
 */
#define MIN_SYSTICK (configCPU_CLOCK_HZ / 1000000 /* ticks / us */ * 10 /* us */)

/*
 * Sleep-check function
 *
 * Your code should over-ride this weak function and return E_NO_ERROR if
 * tickless sleep is permissible (ie. no UART/SPI/I2C activity). Any other
 * return code will prevent FreeRTOS from entering tickless idle.
 */
int freertos_permit_tickless(void)
{
    /* Can not disable BLE DBB and 32 MHz clock while trim procedure is ongoing */
    if (MXC_WUT_TrimPending(MXC_WUT0) != E_NO_ERROR) {
        return E_BUSY;
    }

    /* Figure out if the UART is active */
    if (PalUartGetState(PAL_UART_ID_TERMINAL) == PAL_UART_STATE_BUSY) {
        return E_BUSY;
    }

    /* Prevent characters from being corrupted if still transmitting,
      UART will shutdown in deep sleep  */
    if (MXC_UART_GetActive(MXC_UART_GET_UART(CONSOLE_UART)) != E_NO_ERROR) {
        return E_BUSY;
    }

    return E_NO_ERROR;
}

/*
 * This function overrides vPortSuppressTicksAndSleep in portable/.../ARM_CM4F/port.c
 *
 * DEEPSLEEP mode will stop SysTick from counting, so that can't be
 * used to wake up. Instead, calculate a wake-up period for the WUT to
 * interrupt the WFI and continue execution.
 *
 */
void vPortSuppressTicksAndSleep(TickType_t xExpectedIdleTime)
{
    uint32_t preCapture, postCapture, schUsec, dsTicks, dsWutTicks;
    uint64_t bleSleepTicks, idleTicks, dsSysTickPeriods, schUsecElapsed;
    bool_t schTimerActive;

    /* We do not currently handle to case where the WUT is slower than the RTOS tick */
    MXC_ASSERT(configRTC_TICK_RATE_HZ >= configTICK_RATE_HZ);

    if (SysTick->VAL < MIN_SYSTICK) {
        /* Avoid sleeping too close to a systick interrupt */
        return;
    }

    /* Calculate the number of WUT ticks, but we need one to synchronize */
    idleTicks = (uint64_t)(xExpectedIdleTime - 1) * (uint64_t)configRTC_TICK_RATE_HZ /
                (uint64_t)configTICK_RATE_HZ;

    if (idleTicks > MAX_WUT_TICKS) {
        idleTicks = MAX_WUT_TICKS;
    }

    /* Check to see if we meet the minimum requirements for deep sleep */
    if (idleTicks < (MIN_WUT_TICKS + WAKEUP_US)) {
        return;
    }

    /* Enter a critical section but don't use the taskENTER_CRITICAL()
       method as that will mask interrupts that should exit sleep mode. */
    __asm volatile("cpsid i");

    /* If a context switch is pending or a task is waiting for the scheduler
       to be unsuspended then abandon the low power entry. */
    /* Also check the MXC drivers for any in-progress activity */
    if ((eTaskConfirmSleepModeStatus() == eAbortSleep) ||
        (freertos_permit_tickless() != E_NO_ERROR)) {
        /* Re-enable interrupts - see comments above the cpsid instruction()
           above. */
        __asm volatile("cpsie i");

        return;
    }

    /* Determine if the Bluetooth scheduler is running */
    if (PalTimerGetState() == PAL_TIMER_STATE_BUSY) {
        schTimerActive = TRUE;
    } else {
        schTimerActive = FALSE;
    }

    if (!schTimerActive) {
        uint32_t ts;
        if (PalBbGetTimestamp(&ts)) {
            /*Determine if PalBb is active, return if we get a valid time stamp indicating 
             * that the scheduler is waiting for a PalBb event */

            /* Re-enable interrupts - see comments above the cpsid instruction()
               above. */
            __asm volatile("cpsie i");

            return;
        }
    }

    /* Disable SysTick */
    SysTick->CTRL &= ~(SysTick_CTRL_ENABLE_Msk);

    /* Enable wakeup from WUT */
    NVIC_EnableIRQ(WUT_IRQn);
    MXC_LP_EnableWUTAlarmWakeup();

    /* Determine if we need to snapshot the PalBb clock */
    if (schTimerActive) {
        /* Snapshot the current WUT value with the PalBb clock */
        MXC_WUT_Store(MXC_WUT0);
        preCapture = MXC_WUT_GetCount(MXC_WUT0);
        schUsec = PalTimerGetExpTime();

        /* Adjust idleTicks for the time it takes to restart the BLE hardware */
        idleTicks -= ((WAKEUP_US)*configRTC_TICK_RATE_HZ / 1000000);

        /* Calculate the time to the next BLE scheduler event */
        if (schUsec < WAKEUP_US) {
            bleSleepTicks = 0;
        } else {
            bleSleepTicks = ((uint64_t)schUsec - (uint64_t)WAKEUP_US) *
                            (uint64_t)configRTC_TICK_RATE_HZ / (uint64_t)BB_CLK_RATE_HZ;
        }
    } else {
        /* Snapshot the current WUT value */
        MXC_WUT_Edge(MXC_WUT0);
        preCapture = MXC_WUT_GetCount(MXC_WUT0);
        bleSleepTicks = 0;
        schUsec = 0;
    }

    /* Sleep for the shortest tick duration */
    if ((schTimerActive) && (bleSleepTicks < idleTicks)) {
        dsTicks = bleSleepTicks;
    } else {
        dsTicks = idleTicks;
    }

    /* Bound the deep sleep time */
    if (dsTicks > MAX_WUT_TICKS) {
        dsTicks = MAX_WUT_TICKS;
    }

    /* Don't deep sleep if we don't have time */
    if (dsTicks >= MIN_WUT_TICKS) {
        /* Arm the WUT interrupt */
        MXC_WUT->cmp = preCapture + dsTicks;

        if (schTimerActive) {
            /* Stop the BLE scheduler timer */
            PalTimerStop();

            /* Shutdown BB hardware */
            PalBbDisable();
        }

        LED_Off(SLEEP_LED);
        LED_Off(DEEPSLEEP_LED);

        MXC_LP_EnterStandbyMode();

        LED_On(DEEPSLEEP_LED);
        LED_On(SLEEP_LED);

        if (schTimerActive) {
            /* Enable and restore the BB hardware */
            PalBbEnable();

            PalBbRestore();

            /* Restore the BB counter */
            MXC_WUT_RestoreBBClock(MXC_WUT0, BB_CLK_RATE_HZ);

            /* Restart the BLE scheduler timer */
            dsWutTicks = MXC_WUT->cnt - preCapture;
            schUsecElapsed =
                (uint64_t)dsWutTicks * (uint64_t)1000000 / (uint64_t)configRTC_TICK_RATE_HZ;

            int palTimerStartTicks = schUsec - schUsecElapsed;
            if (palTimerStartTicks < 1) {
                palTimerStartTicks = 1;
            }
            PalTimerStart(palTimerStartTicks);
        }
    }

    /* Recalculate dsWutTicks for the FreeRTOS tick counter update */
    MXC_WUT_Edge(MXC_WUT0);
    postCapture = MXC_WUT_GetCount(MXC_WUT0);
    dsWutTicks = postCapture - preCapture;

    /*
     * Advance ticks by # actually elapsed
     */
    dsSysTickPeriods =
        (uint64_t)dsWutTicks * (uint64_t)configTICK_RATE_HZ / (uint64_t)configRTC_TICK_RATE_HZ;
    vTaskStepTick(dsSysTickPeriods);

    /* Re-enable SysTick */
    SysTick->CTRL |= SysTick_CTRL_ENABLE_Msk;

    /* Re-enable interrupts - see comments above the cpsid instruction()
       above. */
    __asm volatile("cpsie i");
}
