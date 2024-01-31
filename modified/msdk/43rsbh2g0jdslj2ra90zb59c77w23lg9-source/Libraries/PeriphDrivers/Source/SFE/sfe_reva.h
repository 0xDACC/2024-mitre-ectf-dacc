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

#ifndef LIBRARIES_PERIPHDRIVERS_SOURCE_SFE_SFE_REVA_H_
#define LIBRARIES_PERIPHDRIVERS_SOURCE_SFE_SFE_REVA_H_

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include "mxc_device.h"
#include "mxc_assert.h"
#include "mxc_sys.h"
#include "mxc_delay.h"
#include "sfe.h"
#include "sfe_reva_regs.h"

int MXC_SFE_RevA_Init(void);
int MXC_SFE_RevA_Shutdown(void);
int MXC_SFE_RevA_ReadEnable(mxc_sfe_reva_regs_t *sfe);
int MXC_SFE_RevA_WriteEnable(mxc_sfe_reva_regs_t *sfe);
int MXC_SFE_RevA_SetFlashAddress(mxc_sfe_reva_regs_t *sfe, uint32_t baseAdd, uint32_t topAdd);
int MXC_SFE_RevA_SetRAMAddress(mxc_sfe_reva_regs_t *sfe, uint32_t baseAdd, uint32_t topAdd);
int MXC_SFE_RevA_SetHostAddress(mxc_sfe_reva_regs_t *sfe, uint32_t RAMAdd, uint32_t FLASHAdd);

#endif // LIBRARIES_PERIPHDRIVERS_SOURCE_SFE_SFE_REVA_H_
