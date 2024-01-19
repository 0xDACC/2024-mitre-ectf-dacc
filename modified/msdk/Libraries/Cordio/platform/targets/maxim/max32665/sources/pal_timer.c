/*************************************************************************************************/
/*!
 * \file
 *
 * \brief      Timer driver
 *
 * Copyright (c) 2019-2020 Packetcraft, Inc.  All rights reserved.
 * Packetcraft, Inc. confidential and proprietary.
 *
 * IMPORTANT.  Your use of this file is governed by a Software License Agreement
 * ("Agreement") that must be accepted in order to download or otherwise receive a
 * copy of this file.  You may not use or copy this file for any purpose other than
 * as described in the Agreement.  If you do not agree to all of the terms of the
 * Agreement do not use this file and delete all copies in your possession or control;
 * if you do not have a copy of the Agreement, you must contact Packetcraft, Inc. prior
 * to any use, copying or further distribution of this software.
 */
/*************************************************************************************************/

#include "pal_timer.h"
#include "pal_led.h"
#include "pal_sys.h"
#include "pal_bb.h"
#include "tmr.h"
#include "lp.h"
#include "gcr_regs.h"
#include "mxc_device.h"
#include "wsf_trace.h"
#include "wut.h"
#include "wut_regs.h"
#include "wsf_cs.h"
/**************************************************************************************************
  Macros
**************************************************************************************************/
#ifdef DEBUG

/*! \brief      Parameter and state check. */
#define PAL_TIMER_CHECK(expr)                         \
    {                                                 \
        if (!(expr)) {                                \
            palTimerCb.state = PAL_TIMER_STATE_ERROR; \
            while (1)                                 \
                ;                                     \
        }                                             \
    }

#else

/*! \brief      Parameter and state check (disabled). */
#define PAL_TIMER_CHECK(expr)

#endif

/* Sleep timer */
#ifndef PAL_SLEEP_TMR_IDX
#define PAL_SLEEP_TMR_IDX 1
#endif

#define PAL_SLEEP_TMR MXC_TMR_GET_TMR(PAL_SLEEP_TMR_IDX)
#define PAL_SLEEP_TMR_IRQn MXC_TMR_GET_IRQ(PAL_SLEEP_TMR_IDX)
/* Scheduler timer*/
#if defined(USE_SHARED_WUT)
/* PAL Timer and PAL RTC will share WUT timer*/
#define PAL_TMR_IRQn (WUT_IRQn)
#else
#ifndef PAL_TMR_IDX
#define PAL_TMR_IDX 0
#endif
#if (PAL_TMR_IDX == PAL_SLEEP_TMR_IDX)
#error "Must use a different timer for sleep"
#endif

#define PAL_TMR MXC_TMR_GET_TMR(PAL_TMR_IDX)
#define PAL_TMR_IRQn MXC_TMR_GET_IRQ(PAL_TMR_IDX)
#endif

#define PAL_TMR_CALIB_TIME_US 100000
/**************************************************************************************************
  Global Variables
**************************************************************************************************/

/*! \brief      Scheduler timer driver control block. */
static struct {
    PalTimerState_t state; /*!< State. */
    PalTimerCompCback_t expCback; /*!< Timer expiry call back function. */
    int usecDiff; /*!< Adjustment factor for timer. */
} palTimerCb;

/**************************************************************************************************
  External Functions: Initialization
**************************************************************************************************/

/*************************************************************************************************/
/*!
 *  \brief      Timer interrupt handler dedicated to scheduler timer.
 *
 *  \return     None.
 */
/*************************************************************************************************/
#if defined(USE_SHARED_WUT)
__attribute__((weak)) void WUT_IRQHandler(void)
{
    MXC_WUT_Handler();
    PalTimerIRQCallBack();
    NVIC_ClearPendingIRQ(WUT_IRQn);
}
#else
#if (PAL_TMR_IDX == 5)
void TMR5_IRQHandler(void)
#elif (PAL_TMR_IDX == 4)
void TMR4_IRQHandler(void)
#elif (PAL_TMR_IDX == 3)
void TMR3_IRQHandler(void)
#elif (PAL_TMR_IDX == 2)
void TMR2_IRQHandler(void)
#elif (PAL_TMR_IDX == 1)
void TMR1_IRQHandler(void)
#else
void TMR0_IRQHandler(void)
#endif
{
    PalLedOn(PAL_LED_ID_CPU_ACTIVE);

    /* Check hardware status */
    PAL_TIMER_CHECK(palTimerCb.state == PAL_TIMER_STATE_BUSY);

    /* Disable and clear PAL_TMR interrupt */
    NVIC_DisableIRQ(PAL_TMR_IRQn);
    MXC_TMR_ClearFlags(PAL_TMR);

    palTimerCb.state = PAL_TIMER_STATE_READY;

    if (palTimerCb.expCback) {
        palTimerCb.expCback();
    }
}
#endif
void PalTimerIRQCallBack(void)
{
#if defined(USE_SHARED_WUT)
    PalLedOn(PAL_LED_ID_CPU_ACTIVE);

    /* Check hardware status */
    if (palTimerCb.state == PAL_TIMER_STATE_BUSY) {
        PalSysSetIdle();
        palTimerCb.state = PAL_TIMER_STATE_READY;

        if (palTimerCb.expCback) {
            palTimerCb.expCback();
        }
    }
#endif
}

/*************************************************************************************************/
/*!
 *  \brief      Timer interrupt handler dedicated to sleep timer.
 *
 *  \return     None.
 */
/*************************************************************************************************/
#if (PAL_SLEEP_TMR_IDX == 5)
void TMR5_IRQHandler(void)
#elif (PAL_SLEEP_TMR_IDX == 4)
void TMR4_IRQHandler(void)
#elif (PAL_SLEEP_TMR_IDX == 3)
void TMR3_IRQHandler(void)
#elif (PAL_SLEEP_TMR_IDX == 2)
void TMR2_IRQHandler(void)
#elif (PAL_SLEEP_TMR_IDX == 1)
void TMR1_IRQHandler(void)
#else
void TMR0_IRQHandler(void)
#endif
{
    PalLedOn(PAL_LED_ID_CPU_ACTIVE);

    /* Disable and clear PAL_TMR interrupt */
    NVIC_DisableIRQ(PAL_SLEEP_TMR_IRQn);
    MXC_TMR_ClearFlags(PAL_SLEEP_TMR);
}

/*************************************************************************************************/
/*!
 *  \brief      Initialize timer resources.
 *
 *  \return     None.
 */
/*************************************************************************************************/

void PalTimerInit(PalTimerCompCback_t expCback)
{
    bool_t palBbState;
    uint32_t tickStart, tickEnd;

    PAL_TIMER_CHECK(palTimerCb.state == PAL_TIMER_STATE_UNINIT);
    PAL_TIMER_CHECK(expCback != NULL);

#if defined(USE_SHARED_WUT)
    APP_TRACE_INFO0("PalTimerInit: Use shared WUT");
    if (!PalSharedTimerIsInit()) {
        /* Init WUT */
        mxc_wut_cfg_t cfg;
        cfg.mode = MXC_WUT_MODE_COMPARE;
        cfg.cmp_cnt = 0;
        MXC_WUT_Init(MXC_WUT_PRES_1);
        MXC_WUT_Config(&cfg);

        NVIC_ClearPendingIRQ(WUT_IRQn);
        NVIC_SetPriority(WUT_IRQn, 0);
        NVIC_EnableIRQ(WUT_IRQn);

        /* Enable WUT */
        MXC_WUT_Enable();
        MXC_LP_EnableWUTAlarmWakeup();
        PalSharedTimerInitState(TRUE);
    }
#else
    mxc_tmr_cfg_t tmr_cfg;
    tmr_cfg.pres = TMR_PRES_1;
    tmr_cfg.mode = TMR_MODE_ONESHOT;
    tmr_cfg.pol = 0;

    NVIC_ClearPendingIRQ(PAL_TMR_IRQn);
    NVIC_DisableIRQ(PAL_TMR_IRQn);
    MXC_TMR_ClearFlags(PAL_TMR);

    MXC_TMR_Stop(PAL_TMR);
    MXC_TMR_Init(PAL_TMR, &tmr_cfg);
#endif

    /* Make sure the BB clock is running */
    if (PalBbGetCurrentTime() == 0) {
        palBbState = FALSE;
        PalBbEnable();
    } else {
        palBbState = TRUE;
    }

    /* Wait for the clock to run */
    while (PalBbGetCurrentTime() == 0) {}

    /* Save the ticks for PAL_TMR_CALIB_TIME usec */
    tickStart = PalBbGetCurrentTime();
#if defined(USE_SHARED_WUT)
    MXC_WUT_Delay_MS(100);
#else
    MXC_TMR_Delay(PAL_TMR, PAL_TMR_CALIB_TIME_US);
#endif

    tickEnd = PalBbGetCurrentTime();

    /* Save the difference */
    palTimerCb.usecDiff = PAL_TMR_CALIB_TIME_US - (tickEnd - tickStart);

    /* Restore the BB state */
    if (!palBbState) {
        PalBbDisable();
    }

    palTimerCb.expCback = expCback;
    palTimerCb.state = PAL_TIMER_STATE_READY;
}

/*************************************************************************************************/
/*!
 *  \brief      Restore timer state after deep sleep.
 *
 *  \param      expUsec     Countdown time in microseconds, adjusted for sleep time.
 *
 *  \return     None.
 */
/*************************************************************************************************/
void PalTimerRestore(uint32_t expUsec)
{
    palTimerCb.state = PAL_TIMER_STATE_UNINIT;
    PalTimerInit(palTimerCb.expCback);
    PalTimerStart(expUsec);
}

/*************************************************************************************************/
/*!
 *  \brief      De-Initialize timer resources.
 *
 *  \return     None.
 */
/*************************************************************************************************/
void PalTimerDeInit(void)
{
    NVIC_DisableIRQ(PAL_TMR_IRQn);
#if defined(USE_SHARED_WUT)
    MXC_WUT_Disable();
#else
    MXC_TMR_Shutdown(PAL_TMR);
#endif
    palTimerCb.state = PAL_TIMER_STATE_UNINIT;
}

/**************************************************************************************************
  External Functions: Control and Status
**************************************************************************************************/

/*************************************************************************************************/
/*!
 *  \brief      Return scheduler timer state.
 
 */
/*************************************************************************************************/
void PalTimerExecCallback(void)
{
    if (palTimerCb.expCback) {
        palTimerCb.expCback();
    }
}

/*************************************************************************************************/
/*!
 *  \brief      Return scheduler timer state.
 *
 *  \return     state.
 */
/*************************************************************************************************/
PalTimerState_t PalTimerGetState(void)
{
    return palTimerCb.state;
}

/*************************************************************************************************/
/*!
 *  \brief      Register a callback and set a timer.
 *
 *  \param      expUsec     Countdown time in microseconds.
 *
 *  \return     None.
 */
/*************************************************************************************************/
void PalTimerStart(uint32_t expUsec)
{
    PAL_TIMER_CHECK(palTimerCb.state == PAL_TIMER_STATE_READY);
    PAL_TIMER_CHECK(expUsec != 0);
    /* Make sure we don't wrap the timeout */
    if (expUsec == 0) {
        expUsec = 1;
    }

    /* Convert the time based on our calibration */
    expUsec += (expUsec / PAL_TMR_CALIB_TIME_US) * palTimerCb.usecDiff;
#if defined(USE_SHARED_WUT)
    PalSysSetBusy();
    uint64_t volatile compareValue;
    uint32_t ticks;

    MXC_WUT_GetTicks(1, MXC_WUT_UNIT_SEC, &ticks);
    /* Calculate the compare value */
    compareValue = (((uint64_t)expUsec * (uint64_t)32768) / (uint64_t)1000000);
    /* handle wrap around */
    uint32_t adjustedcompareValue = ((MXC_WUT_GetCount() + compareValue) % (0xFFFFFFFF));
    if (adjustedcompareValue < compareValue) {
        /* if wrapped around add 1 */
        adjustedcompareValue++;
    }

    MXC_WUT_SetCompare(adjustedcompareValue);

    /* Clear and enable interrupts */
    NVIC_ClearPendingIRQ(WUT_IRQn);
    NVIC_EnableIRQ(WUT_IRQn);

    palTimerCb.state = PAL_TIMER_STATE_BUSY;
    /* Enable WUT */
    WsfCsEnter();
    MXC_LP_EnableWUTAlarmWakeup();
    WsfCsExit();
#else
    /* Convert the start time to ticks */
    MXC_TMR_SetCount(PAL_TMR, 0);
    MXC_TMR_SetCompare(PAL_TMR, PeripheralClock / 1000000 * expUsec);

    /* Clear and enable interrupts */
    MXC_TMR_ClearFlags(PAL_TMR);
    NVIC_ClearPendingIRQ(PAL_TMR_IRQn);
    NVIC_EnableIRQ(PAL_TMR_IRQn);

    palTimerCb.state = PAL_TIMER_STATE_BUSY;

    MXC_TMR_Start(PAL_TMR);
#endif
}

/*************************************************************************************************/
/*!
 *  \brief      Cancel a timer operation.
 *
 *  \return     None.
 */
/*************************************************************************************************/
void PalTimerStop(void)
{
/* Disable this interrupt */
#if defined(USE_SHARED_WUT)
    NVIC_DisableIRQ(WUT_IRQn);
    NVIC_ClearPendingIRQ(WUT_IRQn);
#else
    MXC_TMR_Stop(PAL_TMR);

    /* Disable this interrupt */
    NVIC_DisableIRQ(PAL_TMR_IRQn);
    MXC_TMR_ClearFlags(PAL_TMR);
#endif

    palTimerCb.state = PAL_TIMER_STATE_READY;
}

/*************************************************************************************************/
/*!
 *  \brief      Sleep and use the timer to wakeup after expUsec micros seconds.
 *
 *  \param      expUsec     Countdown time in microseconds.
 *
 *  \return     None.
 */
/*************************************************************************************************/
void PalTimerSleep(uint32_t expUsec)
{
    mxc_tmr_cfg_t tmr_cfg;

    /* Configure timer */
    tmr_cfg.pres = TMR_PRES_1;
    tmr_cfg.mode = TMR_MODE_ONESHOT;
    tmr_cfg.pol = 0;

    NVIC_ClearPendingIRQ(PAL_SLEEP_TMR_IRQn);
    NVIC_DisableIRQ(PAL_SLEEP_TMR_IRQn);
    MXC_TMR_ClearFlags(PAL_SLEEP_TMR);

    MXC_TMR_Stop(PAL_SLEEP_TMR);
    MXC_TMR_Init(PAL_SLEEP_TMR, &tmr_cfg);

    /* Convert the start time to ticks */
    MXC_TMR_SetCount(PAL_SLEEP_TMR, 0);
    MXC_TMR_SetCompare(PAL_SLEEP_TMR, PeripheralClock / 1000000 * expUsec); /* 7.3728 MHz clock */

    /* Clear and enable interrupts */
    MXC_TMR_ClearFlags(PAL_SLEEP_TMR);
    NVIC_ClearPendingIRQ(PAL_SLEEP_TMR_IRQn);
    NVIC_EnableIRQ(PAL_SLEEP_TMR_IRQn);

    MXC_TMR_Start(PAL_SLEEP_TMR);

    PalLedOff(PAL_LED_ID_CPU_ACTIVE);

    MXC_LP_EnterSleepMode();

    PalLedOn(PAL_LED_ID_CPU_ACTIVE);

    MXC_TMR_Shutdown(PAL_SLEEP_TMR);
}

/*************************************************************************************************/
/*!
 *  \brief      Get the time in microseconds before the next PalTimer expiration.
 *
 *  \return     Time to next PalTimer expiration in micro seconds.
 */
/*************************************************************************************************/
uint32_t PalTimerGetExpTime(void)
{
    uint32_t time;

    /* See if the timer is currently running */
    if (palTimerCb.state != PAL_TIMER_STATE_BUSY) {
        return 0;
    }
#if defined(USE_SHARED_WUT)
    time = MXC_WUT_GetCompare() - MXC_WUT_GetCount();
#else
    time = MXC_TMR_GetCompare(PAL_TMR) - MXC_TMR_GetCount(PAL_TMR);
#endif
    // TODO : should this PeriphralClock be 32768?
    time /= (PeripheralClock / 1000000);

    /* Adjust time based on the calibrated value */
    time = time - ((time / PAL_TMR_CALIB_TIME_US) * palTimerCb.usecDiff);

    return time;
}

/*************************************************************************************************/
/*!
 *  \brief      Configure PAL timer interrupt priority.
 *
 *  \param      priority     Interrupt priority.
 *
 *  \return     None.
 */
/*************************************************************************************************/
void PalTimerSetIRQPriority(uint32_t priority)
{
    NVIC_SetPriority(PAL_TMR_IRQn, priority);
}
