/**
 * @file    aes_key_regs.h
 * @brief   Registers, Bit Masks and Bit Positions for the AES_KEY Peripheral Module.
 * @note    This file is @deprecated.
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

#ifndef LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32650_INCLUDE_AES_KEY_REGS_H_
#define LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32650_INCLUDE_AES_KEY_REGS_H_

#warning "DEPRECATED(1-10-2023): aes_key_regs.h - Scheduled for removal. Please use aeskeys_regs.h."

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
 * @ingroup     aes_key
 * @defgroup    aes_key_registers AES_KEY_Registers
 * @brief       Registers, Bit Masks and Bit Positions for the AES_KEY Peripheral Module.
 * @details     AES Key Registers.
 */

/**
 * @ingroup aes_key_registers
 * Structure type to access the AES_KEY Registers.
 */
#if defined(__GNUC__)
__attribute__((deprecated("mxc_aes_key_regs_t struct and aes_key_regs.h no longer supported. Use aeskeys_regs.h and MXC_AESKEYS (mxc_aeskeys_regs_t) for AES Key Access. 1-10-2023")))
#else
#warning "mxc_aes_key_regs_t struct and aes_key_regs.h no longer supported. Use aeskeys_regs.h and MXC_AESKEYS (mxc_aeskeys_regs_t) for AES Key Access. 1-10-2023"
#endif
typedef struct {
    __IO uint32_t aes_key0[4];          /**< <tt>\b 0x00:</tt> AES_KEY AES_KEY0 Register */
    __R  uint32_t rsv_0x10_0x1f[4];
    __IO uint32_t aes_key1[4];          /**< <tt>\b 0x20:</tt> AES_KEY AES_KEY1 Register */
    __R  uint32_t rsv_0x30_0xff[52];
    __IO uint32_t aes_key2[4];          /**< <tt>\b 0x100:</tt> AES_KEY AES_KEY2 Register */
    __R  uint32_t rsv_0x110_0x17f[28];
    __IO uint32_t aes_key3[4];          /**< <tt>\b 0x180:</tt> AES_KEY AES_KEY3 Register */
} mxc_aes_key_regs_t;


/* Register offsets for module AES_KEY */
/**
 * @ingroup    aes_key_registers
 * @defgroup   AES_KEY_Register_Offsets Register Offsets
 * @brief      AES_KEY Peripheral Register Offsets from the AES_KEY Base Peripheral Address.
 * @{
 */
#define MXC_R_AES_KEY_AES_KEY0             ((uint32_t)0x00000000UL) /**< Offset from AES_KEY Base Address: <tt> 0x0000</tt> */
#define MXC_R_AES_KEY_AES_KEY1             ((uint32_t)0x00000020UL) /**< Offset from AES_KEY Base Address: <tt> 0x0020</tt> */
#define MXC_R_AES_KEY_AES_KEY2             ((uint32_t)0x00000100UL) /**< Offset from AES_KEY Base Address: <tt> 0x0100</tt> */
#define MXC_R_AES_KEY_AES_KEY3             ((uint32_t)0x00000180UL) /**< Offset from AES_KEY Base Address: <tt> 0x0180</tt> */
/**@} end of group aes_key_registers */

#ifdef __cplusplus
}
#endif

#endif // LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32650_INCLUDE_AES_KEY_REGS_H_
