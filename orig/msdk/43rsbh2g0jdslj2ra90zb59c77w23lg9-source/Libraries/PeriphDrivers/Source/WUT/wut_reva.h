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

#ifndef LIBRARIES_PERIPHDRIVERS_SOURCE_WUT_WUT_REVA_H_
#define LIBRARIES_PERIPHDRIVERS_SOURCE_WUT_WUT_REVA_H_

/* **** Includes **** */
#include <stdint.h>
#include "mxc_device.h"
#include "mxc_assert.h"
#include "mxc_sys.h"
#include "wut.h"
#include "wut_reva_regs.h"
#include "gcr_regs.h"

/**
 * @brief Wakeup Timer prescaler values
 */
typedef enum {
    MXC_WUT_REVA_PRES_1 = MXC_S_WUT_REVA_CTRL_PRES_DIV1, /// Divide input clock by 1
    MXC_WUT_REVA_PRES_2 = MXC_S_WUT_REVA_CTRL_PRES_DIV2, /// Divide input clock by 2
    MXC_WUT_REVA_PRES_4 = MXC_S_WUT_REVA_CTRL_PRES_DIV4, /// Divide input clock by 4
    MXC_WUT_REVA_PRES_8 = MXC_S_WUT_REVA_CTRL_PRES_DIV8, /// Divide input clock by 8
    MXC_WUT_REVA_PRES_16 = MXC_S_WUT_REVA_CTRL_PRES_DIV16, /// Divide input clock by 16
    MXC_WUT_REVA_PRES_32 = MXC_S_WUT_REVA_CTRL_PRES_DIV32, /// Divide input clock by 32
    MXC_WUT_REVA_PRES_64 = MXC_S_WUT_REVA_CTRL_PRES_DIV64, /// Divide input clock by 64
    MXC_WUT_REVA_PRES_128 = MXC_S_WUT_REVA_CTRL_PRES_DIV128, /// Divide input clock by 128
    MXC_WUT_REVA_PRES_256 = MXC_F_WUT_REVA_CTRL_PRES3 |
                            MXC_S_WUT_REVA_CTRL_PRES_DIV1, /// Divide input clock by 256
    MXC_WUT_REVA_PRES_512 = MXC_F_WUT_REVA_CTRL_PRES3 |
                            MXC_S_WUT_REVA_CTRL_PRES_DIV2, /// Divide input clock by 512
    MXC_WUT_REVA_PRES_1024 = MXC_F_WUT_REVA_CTRL_PRES3 |
                             MXC_S_WUT_REVA_CTRL_PRES_DIV4, /// Divide input clock by 1024
    MXC_WUT_REVA_PRES_2048 = MXC_F_WUT_REVA_CTRL_PRES3 |
                             MXC_S_WUT_REVA_CTRL_PRES_DIV8, /// Divide input clock by 2048
    MXC_WUT_REVA_PRES_4096 = MXC_F_WUT_REVA_CTRL_PRES3 |
                             MXC_S_WUT_REVA_CTRL_PRES_DIV16 /// Divide input clock by 4096
} mxc_wut_reva_pres_t;

/**
 * @brief Wakeup Timer modes
 */
typedef enum {
    MXC_WUT_REVA_MODE_ONESHOT = MXC_V_WUT_REVA_CTRL_TMODE_ONESHOT, /// Wakeup Timer Mode ONESHOT
    MXC_WUT_REVA_MODE_CONTINUOUS =
        MXC_V_WUT_REVA_CTRL_TMODE_CONTINUOUS, /// Wakeup Timer Mode CONTINUOUS
} mxc_wut_reva_mode_t;

/**
 * @brief Wakeup Timer units of time enumeration
 */
typedef enum {
    MXC_WUT_REVA_UNIT_NANOSEC = 0, /**< Nanosecond Unit Indicator. */
    MXC_WUT_REVA_UNIT_MICROSEC, /**< Microsecond Unit Indicator. */
    MXC_WUT_REVA_UNIT_MILLISEC, /**< Millisecond Unit Indicator. */
    MXC_WUT_REVA_UNIT_SEC /**< Second Unit Indicator. */
} mxc_wut_reva_unit_t;

/**
 * @brief Wakeup Timer Configuration
 */
typedef struct {
    mxc_wut_reva_mode_t mode; /// Desired timer mode
    uint32_t cmp_cnt; /// Compare register value in timer ticks
} mxc_wut_reva_cfg_t;

/* **** Functions **** */
void MXC_WUT_RevA_Init(mxc_wut_reva_regs_t *wut, mxc_wut_reva_pres_t pres);

void MXC_WUT_RevA_Shutdown(mxc_wut_reva_regs_t *wut);

void MXC_WUT_RevA_Enable(mxc_wut_reva_regs_t *wut);

void MXC_WUT_RevA_Disable(mxc_wut_reva_regs_t *wut);

void MXC_WUT_RevA_Config(mxc_wut_reva_regs_t *wut, const mxc_wut_reva_cfg_t *cfg);

uint32_t MXC_WUT_RevA_GetCompare(mxc_wut_reva_regs_t *wut);

uint32_t MXC_WUT_RevA_GetCapture(mxc_wut_reva_regs_t *wut);

uint32_t MXC_WUT_RevA_GetCount(mxc_wut_reva_regs_t *wut);

void MXC_WUT_RevA_IntClear(mxc_wut_reva_regs_t *wut);

uint32_t MXC_WUT_RevA_IntStatus(mxc_wut_reva_regs_t *wut);

void MXC_WUT_RevA_SetCompare(mxc_wut_reva_regs_t *wut, uint32_t cmp_cnt);

void MXC_WUT_RevA_SetCount(mxc_wut_reva_regs_t *wut, uint32_t cnt);

int MXC_WUT_RevA_GetTicks(mxc_wut_reva_regs_t *wut, uint32_t timerClock, uint32_t time,
                          mxc_wut_reva_unit_t units, uint32_t *ticks);

int MXC_WUT_RevA_GetTime(mxc_wut_reva_regs_t *wut, uint32_t timerClock, uint32_t ticks,
                         uint32_t *time, mxc_wut_reva_unit_t *units);

void MXC_WUT_RevA_Edge(mxc_wut_reva_regs_t *wut);

void MXC_WUT_RevA_Store(mxc_wut_reva_regs_t *wut);

void MXC_WUT_RevA_RestoreBBClock(mxc_wut_reva_regs_t *wut, uint32_t dbbFreq, uint32_t timerClock);

uint32_t MXC_WUT_RevA_GetSleepTicks(mxc_wut_reva_regs_t *wut);

void MXC_WUT_RevA_Delay_MS(mxc_wut_reva_regs_t *wut, uint32_t waitMs, uint32_t timerClock);

#endif // LIBRARIES_PERIPHDRIVERS_SOURCE_WUT_WUT_REVA_H_
