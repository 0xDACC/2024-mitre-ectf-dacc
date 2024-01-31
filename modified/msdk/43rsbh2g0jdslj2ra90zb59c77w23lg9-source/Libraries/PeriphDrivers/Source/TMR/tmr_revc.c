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

/* **** Includes **** */
#include <stddef.h>
#include "mxc_assert.h"
#include "tmr.h"
#include "tmr_revc.h"
#include "gpio.h"
#include "mxc_pins.h"
#include "mxc_lock.h"

/* **** Definitions **** */

/* **** Functions **** */
int MXC_TMR_RevC_Init(mxc_tmr_regs_t *tmr, mxc_tmr_cfg_t *cfg)
{
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    MXC_ASSERT(tmr_id >= 0);

    if (cfg == NULL) {
        return E_NULL_PTR;
    }

    // Clear interrupt flag
    tmr->intr |= MXC_F_TMR_INTR_IRQ;

    // Set the prescaler
    switch (cfg->pres) {
    case TMR_PRES_1:
        tmr->cn |= (MXC_S_TMR_CN_PRES_DIV_BY_1);
        break;

    case TMR_PRES_2:
        tmr->cn |= (MXC_S_TMR_CN_PRES_DIV_BY_2);
        break;

    case TMR_PRES_4:
        tmr->cn |= (MXC_S_TMR_CN_PRES_DIV_BY_4);
        break;

    case TMR_PRES_8:
        tmr->cn |= (MXC_S_TMR_CN_PRES_DIV_BY_8);
        break;

    case TMR_PRES_16:
        tmr->cn |= (MXC_S_TMR_CN_PRES_DIV_BY_16);
        break;

    case TMR_PRES_32:
        tmr->cn |= (MXC_S_TMR_CN_PRES_DIV_BY_32);
        break;

    case TMR_PRES_64:
        tmr->cn |= (MXC_S_TMR_CN_PRES_DIV_BY_64);
        break;

    case TMR_PRES_128:
        tmr->cn |= (MXC_S_TMR_CN_PRES_DIV_BY_128);
        break;

    case TMR_PRES_256:
        tmr->cn |= (MXC_S_TMR_CN_PRES_DIV_BY_256);
        break;

    case TMR_PRES_512:
        tmr->cn |= (MXC_S_TMR_CN_PRES_DIV_BY_512);
        break;

    case TMR_PRES_1024:
        tmr->cn |= (MXC_S_TMR_CN_PRES_DIV_BY_1024);
        break;

    case TMR_PRES_2048:
        tmr->cn |= (MXC_S_TMR_CN_PRES_DIV_BY_2048);
        break;

    case TMR_PRES_4096:
        tmr->cn |= (MXC_S_TMR_CN_PRES_DIV_BY_4096);
        break;

    case TMR_PRES_8192:
        tmr->cn |= (MXC_S_TMR_CN_PRES_DIV_BY_8192);
        break;
    }

    MXC_TMR_RevC_ConfigGeneric(tmr, cfg);

    return E_NO_ERROR;
}

void MXC_TMR_RevC_ConfigGeneric(mxc_tmr_regs_t *tmr, mxc_tmr_cfg_t *cfg)
{
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    MXC_ASSERT(tmr_id >= 0);

    if (cfg == NULL) {
        return;
    }

    tmr->cn |= (MXC_F_TMR_CN_TEN);
    tmr->cn |= (cfg->mode << MXC_F_TMR_CN_TMODE_POS);
    tmr->cn |= (cfg->pol << MXC_F_TMR_CN_TPOL_POS);
    //enable timer interrupt if needed
    tmr->cnt = 0x1;
    tmr->cmp = (cfg->cmp_cnt);
}

void MXC_TMR_RevC_Shutdown(mxc_tmr_regs_t *tmr)
{
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    MXC_ASSERT(tmr_id >= 0);

    // Disable timer and clear settings
    tmr->cn = 0;
}

void MXC_TMR_RevC_Start(mxc_tmr_regs_t *tmr)
{
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    MXC_ASSERT(tmr_id >= 0);

    tmr->cn |= MXC_F_TMR_CN_TEN;
}

void MXC_TMR_RevC_Stop(mxc_tmr_regs_t *tmr)
{
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    MXC_ASSERT(tmr_id >= 0);

    tmr->cn &= ~MXC_F_TMR_CN_TEN;
}

int MXC_TMR_RevC_SetPWM(mxc_tmr_regs_t *tmr, uint32_t pwm)
{
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    MXC_ASSERT(tmr_id >= 0);

    if (pwm > (tmr->cmp)) {
        return E_BAD_PARAM;
    }

    while (tmr->cnt >= pwm) {}

    tmr->pwm = pwm;

    return E_NO_ERROR;
}

uint32_t MXC_TMR_RevC_GetCompare(mxc_tmr_regs_t *tmr)
{
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    MXC_ASSERT(tmr_id >= 0);

    return tmr->cmp;
}

uint32_t MXC_TMR_RevC_GetCapture(mxc_tmr_regs_t *tmr)
{
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    MXC_ASSERT(tmr_id >= 0);

    return tmr->pwm; //check this
}

uint32_t MXC_TMR_RevC_GetCount(mxc_tmr_regs_t *tmr)
{
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    MXC_ASSERT(tmr_id >= 0);

    return tmr->cnt;
}

uint32_t MXC_TMR_RevC_GetPeriod(mxc_tmr_regs_t *tmr, mxc_tmr_clock_t clock, uint32_t prescalar,
                                uint32_t frequency)
{
    uint32_t periodTicks;
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    MXC_ASSERT(tmr_id >= 0);

    switch (clock) {
    case MXC_TMR_EXT_CLK:
        periodTicks = 32768 / (frequency * prescalar);
        break;

    case MXC_TMR_HFIO_CLK:
        periodTicks = PeripheralClock / (frequency * prescalar);
        break;

    case MXC_TMR_NANORING_CLK:
        periodTicks = 8000 / (frequency * prescalar);
        break;

    default:
        return E_BAD_PARAM;
        break;
    }
    return periodTicks;
}

void MXC_TMR_RevC_ClearFlags(mxc_tmr_regs_t *tmr)
{
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    MXC_ASSERT(tmr_id >= 0);

    tmr->intr = 1;
}

uint32_t MXC_TMR_RevC_GetFlags(mxc_tmr_regs_t *tmr)
{
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    MXC_ASSERT(tmr_id >= 0);

    return tmr->intr;
}

void MXC_TMR_RevC_SetCompare(mxc_tmr_regs_t *tmr, uint32_t cmp_cnt)
{
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    MXC_ASSERT(tmr_id >= 0);

    tmr->cmp = cmp_cnt;
}

void MXC_TMR_RevC_SetCount(mxc_tmr_regs_t *tmr, uint32_t cnt)
{
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    MXC_ASSERT(tmr_id >= 0);

    tmr->cnt = cnt;
}

void MXC_TMR_RevC_TO_Start(mxc_tmr_regs_t *tmr, uint32_t us)
{
    uint64_t ticks;
    int clk_shift = 0;
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    MXC_ASSERT(tmr_id >= 0);

    if (us == 0) {
        return;
    }

    ticks = (uint64_t)us * (uint64_t)PeripheralClock / (uint64_t)1000000;

    while (ticks > 0xFFFFFFFFUL) {
        ticks >>= 1;
        ++clk_shift;
    }

    mxc_tmr_pres_t prescale =
        (mxc_tmr_pres_t)(((tmr->cn & MXC_F_TMR_CN_PRES) >> MXC_F_TMR_CN_PRES_POS) |
                         ((((tmr->cn & MXC_F_TMR_CN_PRES3) >> (MXC_F_TMR_CN_PRES3_POS)) << 3)));
    mxc_tmr_cfg_t cfg;

    // Initialize the timer in one-shot mode
    cfg.pres = prescale;
    cfg.clock = MXC_TMR_HFIO_CLK;
    cfg.mode = TMR_MODE_ONESHOT;
    cfg.cmp_cnt = ticks;
    cfg.pol = 0;

    MXC_TMR_Stop(tmr);
    MXC_TMR_Init(tmr, &cfg);
    MXC_TMR_ClearFlags(tmr);
    MXC_TMR_Start(tmr);
}

int MXC_TMR_RevC_GetTime(mxc_tmr_regs_t *tmr, uint32_t ticks, uint32_t *time, mxc_tmr_unit_t *units)
{
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    MXC_ASSERT(tmr_id >= 0);

    uint64_t temp_time = 0;
    uint32_t timerClock = PeripheralClock;
    uint32_t prescale = (((tmr->cn & MXC_F_TMR_CN_PRES) >> MXC_F_TMR_CN_PRES_POS) |
                         ((((tmr->cn & MXC_F_TMR_CN_PRES3) >> (MXC_F_TMR_CN_PRES3_POS)) << 3)));

    temp_time = (uint64_t)ticks * 1000 * (1 << (prescale & 0xF)) / (timerClock / 1000000);

    if (!(temp_time & 0xffffffff00000000)) {
        *time = temp_time;
        *units = TMR_UNIT_NANOSEC;
        return E_NO_ERROR;
    }

    temp_time = (uint64_t)ticks * 1000 * (1 << (prescale & 0xF)) / (timerClock / 1000);

    if (!(temp_time & 0xffffffff00000000)) {
        *time = temp_time;
        *units = TMR_UNIT_MICROSEC;
        return E_NO_ERROR;
    }

    temp_time = (uint64_t)ticks * 1000 * (1 << (prescale & 0xF)) / timerClock;

    if (!(temp_time & 0xffffffff00000000)) {
        *time = temp_time;
        *units = TMR_UNIT_MILLISEC;
        return E_NO_ERROR;
    }

    temp_time = (uint64_t)ticks * (1 << (prescale & 0xF)) / timerClock;

    if (!(temp_time & 0xffffffff00000000)) {
        *time = temp_time;
        *units = TMR_UNIT_SEC;
        return E_NO_ERROR;
    }

    return E_INVALID;
}
