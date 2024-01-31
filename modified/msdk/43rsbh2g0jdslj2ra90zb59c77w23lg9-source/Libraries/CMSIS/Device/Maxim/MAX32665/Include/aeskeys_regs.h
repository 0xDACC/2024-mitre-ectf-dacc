/**
 * @file    aeskeys_regs.h
 * @brief   Registers, Bit Masks and Bit Positions for the AESKEYS Peripheral Module.
 * @note    This file is @generated.
 * @ingroup aeskeys_registers
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

#ifndef LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32665_INCLUDE_AESKEYS_REGS_H_
#define LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32665_INCLUDE_AESKEYS_REGS_H_

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
 * @ingroup     aeskeys
 * @ingroup     aes
 * @defgroup    aeskeys_registers AESKEYS_Registers
 * @brief       Registers, Bit Masks and Bit Positions for the AESKEYS Peripheral Module.
 * @details     AES Key Registers.
 */

/**
 * @ingroup aeskeys_registers
 * Structure type to access the AESKEYS Registers.
 */
typedef struct {
    __IO uint32_t key0;                 /**< <tt>\b 0x000:</tt> AESKEYS KEY0 Register */
    __R  uint32_t rsv_0x4_0x7f[31];
    __IO uint32_t key1;                 /**< <tt>\b 0x080:</tt> AESKEYS KEY1 Register */
    __R  uint32_t rsv_0x84_0xff[31];
    __IO uint32_t key2;                 /**< <tt>\b 0x100:</tt> AESKEYS KEY2 Register */
    __R  uint32_t rsv_0x104_0x17f[31];
    __IO uint32_t key3;                 /**< <tt>\b 0x180:</tt> AESKEYS KEY3 Register */
} mxc_aeskeys_regs_t;

/* Register offsets for module AESKEYS */
/**
 * @ingroup    aeskeys_registers
 * @defgroup   AESKEYS_Register_Offsets Register Offsets
 * @brief      AESKEYS Peripheral Register Offsets from the AESKEYS Base Peripheral Address.
 * @{
 */
#define MXC_R_AESKEYS_KEY0                 ((uint32_t)0x00000000UL) /**< Offset from AESKEYS Base Address: <tt> 0x0000</tt> */
#define MXC_R_AESKEYS_KEY1                 ((uint32_t)0x00000080UL) /**< Offset from AESKEYS Base Address: <tt> 0x0080</tt> */
#define MXC_R_AESKEYS_KEY2                 ((uint32_t)0x00000100UL) /**< Offset from AESKEYS Base Address: <tt> 0x0100</tt> */
#define MXC_R_AESKEYS_KEY3                 ((uint32_t)0x00000180UL) /**< Offset from AESKEYS Base Address: <tt> 0x0180</tt> */
/**@} end of group aeskeys_registers */

#ifdef __cplusplus
}
#endif

#endif // LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32665_INCLUDE_AESKEYS_REGS_H_
