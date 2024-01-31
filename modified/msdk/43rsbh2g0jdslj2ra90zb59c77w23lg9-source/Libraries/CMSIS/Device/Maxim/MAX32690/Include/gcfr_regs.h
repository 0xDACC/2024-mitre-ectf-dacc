/**
 * @file    gcfr_regs.h
 * @brief   Registers, Bit Masks and Bit Positions for the GCFR Peripheral Module.
 * @note    This file is @generated.
 * @ingroup gcfr_registers
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

#ifndef LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32690_INCLUDE_GCFR_REGS_H_
#define LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32690_INCLUDE_GCFR_REGS_H_

/* **** Includes **** */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined (__ICCARM__)
  #pragma system_include
#endif

#if defined (__CC_ARM)
  #pragma anon_unions
#endif
/// @cond
/*
    If types are not defined elsewhere (CMSIS) define them here
*/
#ifndef __IO
#define __IO volatile
#endif
#ifndef __I
#define __I  volatile const
#endif
#ifndef __O
#define __O  volatile
#endif
#ifndef __R
#define __R  volatile const
#endif
/// @endcond

/* **** Definitions **** */

/**
 * @ingroup     gcfr
 * @defgroup    gcfr_registers GCFR_Registers
 * @brief       Registers, Bit Masks and Bit Positions for the GCFR Peripheral Module.
 * @details     Global Control Function Register.
 */

/**
 * @ingroup gcfr_registers
 * Structure type to access the GCFR Registers.
 */
typedef struct {
    __IO uint32_t reg0;                 /**< <tt>\b 0x00:</tt> GCFR REG0 Register */
} mxc_gcfr_regs_t;

/* Register offsets for module GCFR */
/**
 * @ingroup    gcfr_registers
 * @defgroup   GCFR_Register_Offsets Register Offsets
 * @brief      GCFR Peripheral Register Offsets from the GCFR Base Peripheral Address.
 * @{
 */
#define MXC_R_GCFR_REG0                    ((uint32_t)0x00000000UL) /**< Offset from GCFR Base Address: <tt> 0x0000</tt> */
/**@} end of group gcfr_registers */

/**
 * @ingroup  gcfr_registers
 * @defgroup GCFR_REG0 GCFR_REG0
 * @brief    Register 0.
 * @{
 */
#define MXC_F_GCFR_REG0_CKPDRV_POS                     0 /**< REG0_CKPDRV Position */
#define MXC_F_GCFR_REG0_CKPDRV                         ((uint32_t)(0xFUL << MXC_F_GCFR_REG0_CKPDRV_POS)) /**< REG0_CKPDRV Mask */

#define MXC_F_GCFR_REG0_CKNDRV_POS                     4 /**< REG0_CKNDRV Position */
#define MXC_F_GCFR_REG0_CKNDRV                         ((uint32_t)(0xFUL << MXC_F_GCFR_REG0_CKNDRV_POS)) /**< REG0_CKNDRV Mask */

#define MXC_F_GCFR_REG0_RDSDLL_EN_POS                  8 /**< REG0_RDSDLL_EN Position */
#define MXC_F_GCFR_REG0_RDSDLL_EN                      ((uint32_t)(0x1UL << MXC_F_GCFR_REG0_RDSDLL_EN_POS)) /**< REG0_RDSDLL_EN Mask */

/**@} end of group GCFR_REG0_Register */

#ifdef __cplusplus
}
#endif

#endif // LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32690_INCLUDE_GCFR_REGS_H_
