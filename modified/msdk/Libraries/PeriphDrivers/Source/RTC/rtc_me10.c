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

#include <stddef.h>
#include "rtc.h"
#include "rtc_reva.h"
#include "mxc_sys.h"
#include "mxc_delay.h"
#include "mxc_errors.h"

// *****************************************************************************
int MXC_RTC_SetTimeofdayAlarm(uint32_t ras)
{
    return MXC_RTC_RevA_SetTimeofdayAlarm((mxc_rtc_reva_regs_t *)MXC_RTC, ras);
}

// *****************************************************************************
int MXC_RTC_SetSubsecondAlarm(uint32_t rssa)
{
    return MXC_RTC_RevA_SetSubsecondAlarm((mxc_rtc_reva_regs_t *)MXC_RTC, rssa);
}

// *****************************************************************************
int MXC_RTC_Start(void)
{
    return MXC_RTC_RevA_Start((mxc_rtc_reva_regs_t *)MXC_RTC);
}

// *****************************************************************************
int MXC_RTC_Stop(void)
{
    return MXC_RTC_RevA_Stop((mxc_rtc_reva_regs_t *)MXC_RTC);
}

// *****************************************************************************
int MXC_RTC_Init(uint32_t sec, uint8_t ssec)
{
    MXC_SYS_RTCClockEnable();
    MXC_SYS_Reset_Periph(MXC_SYS_RESET_RTC);

    return MXC_RTC_RevA_Init((mxc_rtc_reva_regs_t *)MXC_RTC, sec, (ssec & MXC_F_RTC_SSEC_SSEC));
}

// *****************************************************************************
int MXC_RTC_SquareWaveStart(mxc_rtc_freq_sel_t fq)
{
    MXC_GPIO_Config(&gpio_cfg_rtcsqw);
    return MXC_RTC_RevA_SquareWave((mxc_rtc_reva_regs_t *)MXC_RTC, MXC_RTC_REVA_SQUARE_WAVE_ENABLED,
                                   fq);
}

// *****************************************************************************
int MXC_RTC_SquareWaveStop(void)
{
    return MXC_RTC_RevA_SquareWave((mxc_rtc_reva_regs_t *)MXC_RTC,
                                   MXC_RTC_REVA_SQUARE_WAVE_DISABLED, 0);
}

// *****************************************************************************
int MXC_RTC_EnableInt(uint32_t mask)
{
    return MXC_RTC_RevA_EnableInt((mxc_rtc_reva_regs_t *)MXC_RTC, mask);
}

// *****************************************************************************
int MXC_RTC_DisableInt(uint32_t mask)
{
    return MXC_RTC_RevA_DisableInt((mxc_rtc_reva_regs_t *)MXC_RTC, mask);
}

// *****************************************************************************
int MXC_RTC_Trim(int8_t trm)
{
    /* MAX32650 does not have RTC_TRIM register */
    return E_NOT_SUPPORTED;
}

// *****************************************************************************
int MXC_RTC_GetFlags(void)
{
    return MXC_RTC_RevA_GetFlags((mxc_rtc_reva_regs_t *)MXC_RTC);
}

// *****************************************************************************
int MXC_RTC_ClearFlags(int flags)
{
    return MXC_RTC_RevA_ClearFlags((mxc_rtc_reva_regs_t *)MXC_RTC, flags);
}

// *****************************************************************************
int MXC_RTC_GetSubSecond(void)
{
    return MXC_RTC_RevA_GetSubSecond((mxc_rtc_reva_regs_t *)MXC_RTC);
}

// *****************************************************************************
int MXC_RTC_GetSecond(void)
{
    return MXC_RTC_RevA_GetSecond((mxc_rtc_reva_regs_t *)MXC_RTC);
}

// *****************************************************************************
int MXC_RTC_GetSubSeconds(uint32_t *ssec)
{
    // Ensure valid data is in SSEC register
    MXC_RTC->ctrl &= ~MXC_F_RTC_CTRL_READY;
    while (!(MXC_RTC->ctrl & MXC_F_RTC_CTRL_READY)) {}

    return MXC_RTC_RevA_GetSubSeconds((mxc_rtc_reva_regs_t *)MXC_RTC, ssec);
}

// *****************************************************************************
int MXC_RTC_GetSeconds(uint32_t *sec)
{
    // Ensure valid data is in SEC register
    MXC_RTC->ctrl &= ~MXC_F_RTC_CTRL_READY;
    while (!(MXC_RTC->ctrl & MXC_F_RTC_CTRL_READY)) {}

    return MXC_RTC_RevA_GetSeconds((mxc_rtc_reva_regs_t *)MXC_RTC, sec);
}

// *****************************************************************************
int MXC_RTC_GetTime(uint32_t *sec, uint32_t *subsec)
{
    return MXC_RTC_RevA_GetTime((mxc_rtc_reva_regs_t *)MXC_RTC, sec, subsec);
}

// *****************************************************************************
int MXC_RTC_GetBusyFlag(void)
{
    return MXC_RTC_RevA_GetBusyFlag((mxc_rtc_reva_regs_t *)MXC_RTC);
}

// *****************************************************************************
int MXC_RTC_TrimCrystal(mxc_tmr_regs_t *tmr)
{
    /* MAX32650 does not have RTC_TRIM register */
    return E_NOT_SUPPORTED;
}
