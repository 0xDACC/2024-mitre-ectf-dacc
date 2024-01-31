/**
 * @file    ptg_regs.h
 * @brief   Registers, Bit Masks and Bit Positions for the PTG Peripheral Module.
 * @note    This file is @generated.
 * @ingroup ptg_registers
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

#ifndef LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32690_INCLUDE_PTG_REGS_H_
#define LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32690_INCLUDE_PTG_REGS_H_

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
 * @ingroup     ptg
 * @defgroup    ptg_registers PTG_Registers
 * @brief       Registers, Bit Masks and Bit Positions for the PTG Peripheral Module.
 * @details     Pulse Train Generation
 */

/**
 * @ingroup ptg_registers
 * Structure type to access the PTG Registers.
 */
typedef struct {
    __IO uint32_t enable;               /**< <tt>\b 0x0000:</tt> PTG ENABLE Register */
    __IO uint32_t resync;               /**< <tt>\b 0x0004:</tt> PTG RESYNC Register */
    __IO uint32_t stop_intfl;           /**< <tt>\b 0x0008:</tt> PTG STOP_INTFL Register */
    __IO uint32_t stop_inten;           /**< <tt>\b 0x000C:</tt> PTG STOP_INTEN Register */
    __O  uint32_t safe_en;              /**< <tt>\b 0x0010:</tt> PTG SAFE_EN Register */
    __O  uint32_t safe_dis;             /**< <tt>\b 0x0014:</tt> PTG SAFE_DIS Register */
    __IO uint32_t ready_intfl;          /**< <tt>\b 0x0018:</tt> PTG READY_INTFL Register */
    __IO uint32_t ready_inten;          /**< <tt>\b 0x001C:</tt> PTG READY_INTEN Register */
} mxc_ptg_regs_t;

/* Register offsets for module PTG */
/**
 * @ingroup    ptg_registers
 * @defgroup   PTG_Register_Offsets Register Offsets
 * @brief      PTG Peripheral Register Offsets from the PTG Base Peripheral Address.
 * @{
 */
#define MXC_R_PTG_ENABLE                   ((uint32_t)0x00000000UL) /**< Offset from PTG Base Address: <tt> 0x0000</tt> */
#define MXC_R_PTG_RESYNC                   ((uint32_t)0x00000004UL) /**< Offset from PTG Base Address: <tt> 0x0004</tt> */
#define MXC_R_PTG_STOP_INTFL               ((uint32_t)0x00000008UL) /**< Offset from PTG Base Address: <tt> 0x0008</tt> */
#define MXC_R_PTG_STOP_INTEN               ((uint32_t)0x0000000CUL) /**< Offset from PTG Base Address: <tt> 0x000C</tt> */
#define MXC_R_PTG_SAFE_EN                  ((uint32_t)0x00000010UL) /**< Offset from PTG Base Address: <tt> 0x0010</tt> */
#define MXC_R_PTG_SAFE_DIS                 ((uint32_t)0x00000014UL) /**< Offset from PTG Base Address: <tt> 0x0014</tt> */
#define MXC_R_PTG_READY_INTFL              ((uint32_t)0x00000018UL) /**< Offset from PTG Base Address: <tt> 0x0018</tt> */
#define MXC_R_PTG_READY_INTEN              ((uint32_t)0x0000001CUL) /**< Offset from PTG Base Address: <tt> 0x001C</tt> */
/**@} end of group ptg_registers */

/**
 * @ingroup  ptg_registers
 * @defgroup PTG_ENABLE PTG_ENABLE
 * @brief    Global Enable/Disable Controls for All Pulse Trains
 * @{
 */
#define MXC_F_PTG_ENABLE_PT0_POS                       0 /**< ENABLE_PT0 Position */
#define MXC_F_PTG_ENABLE_PT0                           ((uint32_t)(0x1UL << MXC_F_PTG_ENABLE_PT0_POS)) /**< ENABLE_PT0 Mask */

#define MXC_F_PTG_ENABLE_PT1_POS                       1 /**< ENABLE_PT1 Position */
#define MXC_F_PTG_ENABLE_PT1                           ((uint32_t)(0x1UL << MXC_F_PTG_ENABLE_PT1_POS)) /**< ENABLE_PT1 Mask */

#define MXC_F_PTG_ENABLE_PT2_POS                       2 /**< ENABLE_PT2 Position */
#define MXC_F_PTG_ENABLE_PT2                           ((uint32_t)(0x1UL << MXC_F_PTG_ENABLE_PT2_POS)) /**< ENABLE_PT2 Mask */

#define MXC_F_PTG_ENABLE_PT3_POS                       3 /**< ENABLE_PT3 Position */
#define MXC_F_PTG_ENABLE_PT3                           ((uint32_t)(0x1UL << MXC_F_PTG_ENABLE_PT3_POS)) /**< ENABLE_PT3 Mask */

#define MXC_F_PTG_ENABLE_PT4_POS                       4 /**< ENABLE_PT4 Position */
#define MXC_F_PTG_ENABLE_PT4                           ((uint32_t)(0x1UL << MXC_F_PTG_ENABLE_PT4_POS)) /**< ENABLE_PT4 Mask */

#define MXC_F_PTG_ENABLE_PT5_POS                       5 /**< ENABLE_PT5 Position */
#define MXC_F_PTG_ENABLE_PT5                           ((uint32_t)(0x1UL << MXC_F_PTG_ENABLE_PT5_POS)) /**< ENABLE_PT5 Mask */

#define MXC_F_PTG_ENABLE_PT6_POS                       6 /**< ENABLE_PT6 Position */
#define MXC_F_PTG_ENABLE_PT6                           ((uint32_t)(0x1UL << MXC_F_PTG_ENABLE_PT6_POS)) /**< ENABLE_PT6 Mask */

#define MXC_F_PTG_ENABLE_PT7_POS                       7 /**< ENABLE_PT7 Position */
#define MXC_F_PTG_ENABLE_PT7                           ((uint32_t)(0x1UL << MXC_F_PTG_ENABLE_PT7_POS)) /**< ENABLE_PT7 Mask */

#define MXC_F_PTG_ENABLE_PT8_POS                       8 /**< ENABLE_PT8 Position */
#define MXC_F_PTG_ENABLE_PT8                           ((uint32_t)(0x1UL << MXC_F_PTG_ENABLE_PT8_POS)) /**< ENABLE_PT8 Mask */

#define MXC_F_PTG_ENABLE_PT9_POS                       9 /**< ENABLE_PT9 Position */
#define MXC_F_PTG_ENABLE_PT9                           ((uint32_t)(0x1UL << MXC_F_PTG_ENABLE_PT9_POS)) /**< ENABLE_PT9 Mask */

#define MXC_F_PTG_ENABLE_PT10_POS                      10 /**< ENABLE_PT10 Position */
#define MXC_F_PTG_ENABLE_PT10                          ((uint32_t)(0x1UL << MXC_F_PTG_ENABLE_PT10_POS)) /**< ENABLE_PT10 Mask */

#define MXC_F_PTG_ENABLE_PT11_POS                      11 /**< ENABLE_PT11 Position */
#define MXC_F_PTG_ENABLE_PT11                          ((uint32_t)(0x1UL << MXC_F_PTG_ENABLE_PT11_POS)) /**< ENABLE_PT11 Mask */

#define MXC_F_PTG_ENABLE_PT12_POS                      12 /**< ENABLE_PT12 Position */
#define MXC_F_PTG_ENABLE_PT12                          ((uint32_t)(0x1UL << MXC_F_PTG_ENABLE_PT12_POS)) /**< ENABLE_PT12 Mask */

#define MXC_F_PTG_ENABLE_PT13_POS                      13 /**< ENABLE_PT13 Position */
#define MXC_F_PTG_ENABLE_PT13                          ((uint32_t)(0x1UL << MXC_F_PTG_ENABLE_PT13_POS)) /**< ENABLE_PT13 Mask */

#define MXC_F_PTG_ENABLE_PT14_POS                      14 /**< ENABLE_PT14 Position */
#define MXC_F_PTG_ENABLE_PT14                          ((uint32_t)(0x1UL << MXC_F_PTG_ENABLE_PT14_POS)) /**< ENABLE_PT14 Mask */

#define MXC_F_PTG_ENABLE_PT15_POS                      15 /**< ENABLE_PT15 Position */
#define MXC_F_PTG_ENABLE_PT15                          ((uint32_t)(0x1UL << MXC_F_PTG_ENABLE_PT15_POS)) /**< ENABLE_PT15 Mask */

/**@} end of group PTG_ENABLE_Register */

/**
 * @ingroup  ptg_registers
 * @defgroup PTG_RESYNC PTG_RESYNC
 * @brief    Global Resync (All Pulse Trains) Control
 * @{
 */
#define MXC_F_PTG_RESYNC_PT0_POS                       0 /**< RESYNC_PT0 Position */
#define MXC_F_PTG_RESYNC_PT0                           ((uint32_t)(0x1UL << MXC_F_PTG_RESYNC_PT0_POS)) /**< RESYNC_PT0 Mask */

#define MXC_F_PTG_RESYNC_PT1_POS                       1 /**< RESYNC_PT1 Position */
#define MXC_F_PTG_RESYNC_PT1                           ((uint32_t)(0x1UL << MXC_F_PTG_RESYNC_PT1_POS)) /**< RESYNC_PT1 Mask */

#define MXC_F_PTG_RESYNC_PT2_POS                       2 /**< RESYNC_PT2 Position */
#define MXC_F_PTG_RESYNC_PT2                           ((uint32_t)(0x1UL << MXC_F_PTG_RESYNC_PT2_POS)) /**< RESYNC_PT2 Mask */

#define MXC_F_PTG_RESYNC_PT3_POS                       3 /**< RESYNC_PT3 Position */
#define MXC_F_PTG_RESYNC_PT3                           ((uint32_t)(0x1UL << MXC_F_PTG_RESYNC_PT3_POS)) /**< RESYNC_PT3 Mask */

#define MXC_F_PTG_RESYNC_PT4_POS                       4 /**< RESYNC_PT4 Position */
#define MXC_F_PTG_RESYNC_PT4                           ((uint32_t)(0x1UL << MXC_F_PTG_RESYNC_PT4_POS)) /**< RESYNC_PT4 Mask */

#define MXC_F_PTG_RESYNC_PT5_POS                       5 /**< RESYNC_PT5 Position */
#define MXC_F_PTG_RESYNC_PT5                           ((uint32_t)(0x1UL << MXC_F_PTG_RESYNC_PT5_POS)) /**< RESYNC_PT5 Mask */

#define MXC_F_PTG_RESYNC_PT6_POS                       6 /**< RESYNC_PT6 Position */
#define MXC_F_PTG_RESYNC_PT6                           ((uint32_t)(0x1UL << MXC_F_PTG_RESYNC_PT6_POS)) /**< RESYNC_PT6 Mask */

#define MXC_F_PTG_RESYNC_PT7_POS                       7 /**< RESYNC_PT7 Position */
#define MXC_F_PTG_RESYNC_PT7                           ((uint32_t)(0x1UL << MXC_F_PTG_RESYNC_PT7_POS)) /**< RESYNC_PT7 Mask */

#define MXC_F_PTG_RESYNC_PT8_POS                       8 /**< RESYNC_PT8 Position */
#define MXC_F_PTG_RESYNC_PT8                           ((uint32_t)(0x1UL << MXC_F_PTG_RESYNC_PT8_POS)) /**< RESYNC_PT8 Mask */

#define MXC_F_PTG_RESYNC_PT9_POS                       9 /**< RESYNC_PT9 Position */
#define MXC_F_PTG_RESYNC_PT9                           ((uint32_t)(0x1UL << MXC_F_PTG_RESYNC_PT9_POS)) /**< RESYNC_PT9 Mask */

#define MXC_F_PTG_RESYNC_PT10_POS                      10 /**< RESYNC_PT10 Position */
#define MXC_F_PTG_RESYNC_PT10                          ((uint32_t)(0x1UL << MXC_F_PTG_RESYNC_PT10_POS)) /**< RESYNC_PT10 Mask */

#define MXC_F_PTG_RESYNC_PT11_POS                      11 /**< RESYNC_PT11 Position */
#define MXC_F_PTG_RESYNC_PT11                          ((uint32_t)(0x1UL << MXC_F_PTG_RESYNC_PT11_POS)) /**< RESYNC_PT11 Mask */

#define MXC_F_PTG_RESYNC_PT12_POS                      12 /**< RESYNC_PT12 Position */
#define MXC_F_PTG_RESYNC_PT12                          ((uint32_t)(0x1UL << MXC_F_PTG_RESYNC_PT12_POS)) /**< RESYNC_PT12 Mask */

#define MXC_F_PTG_RESYNC_PT13_POS                      13 /**< RESYNC_PT13 Position */
#define MXC_F_PTG_RESYNC_PT13                          ((uint32_t)(0x1UL << MXC_F_PTG_RESYNC_PT13_POS)) /**< RESYNC_PT13 Mask */

#define MXC_F_PTG_RESYNC_PT14_POS                      14 /**< RESYNC_PT14 Position */
#define MXC_F_PTG_RESYNC_PT14                          ((uint32_t)(0x1UL << MXC_F_PTG_RESYNC_PT14_POS)) /**< RESYNC_PT14 Mask */

#define MXC_F_PTG_RESYNC_PT15_POS                      15 /**< RESYNC_PT15 Position */
#define MXC_F_PTG_RESYNC_PT15                          ((uint32_t)(0x1UL << MXC_F_PTG_RESYNC_PT15_POS)) /**< RESYNC_PT15 Mask */

/**@} end of group PTG_RESYNC_Register */

/**
 * @ingroup  ptg_registers
 * @defgroup PTG_STOP_INTFL PTG_STOP_INTFL
 * @brief    Pulse Train Interrupt Flags
 * @{
 */
#define MXC_F_PTG_STOP_INTFL_PT0_POS                   0 /**< STOP_INTFL_PT0 Position */
#define MXC_F_PTG_STOP_INTFL_PT0                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTFL_PT0_POS)) /**< STOP_INTFL_PT0 Mask */

#define MXC_F_PTG_STOP_INTFL_PT1_POS                   1 /**< STOP_INTFL_PT1 Position */
#define MXC_F_PTG_STOP_INTFL_PT1                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTFL_PT1_POS)) /**< STOP_INTFL_PT1 Mask */

#define MXC_F_PTG_STOP_INTFL_PT2_POS                   2 /**< STOP_INTFL_PT2 Position */
#define MXC_F_PTG_STOP_INTFL_PT2                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTFL_PT2_POS)) /**< STOP_INTFL_PT2 Mask */

#define MXC_F_PTG_STOP_INTFL_PT3_POS                   3 /**< STOP_INTFL_PT3 Position */
#define MXC_F_PTG_STOP_INTFL_PT3                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTFL_PT3_POS)) /**< STOP_INTFL_PT3 Mask */

#define MXC_F_PTG_STOP_INTFL_PT4_POS                   4 /**< STOP_INTFL_PT4 Position */
#define MXC_F_PTG_STOP_INTFL_PT4                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTFL_PT4_POS)) /**< STOP_INTFL_PT4 Mask */

#define MXC_F_PTG_STOP_INTFL_PT5_POS                   5 /**< STOP_INTFL_PT5 Position */
#define MXC_F_PTG_STOP_INTFL_PT5                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTFL_PT5_POS)) /**< STOP_INTFL_PT5 Mask */

#define MXC_F_PTG_STOP_INTFL_PT6_POS                   6 /**< STOP_INTFL_PT6 Position */
#define MXC_F_PTG_STOP_INTFL_PT6                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTFL_PT6_POS)) /**< STOP_INTFL_PT6 Mask */

#define MXC_F_PTG_STOP_INTFL_PT7_POS                   7 /**< STOP_INTFL_PT7 Position */
#define MXC_F_PTG_STOP_INTFL_PT7                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTFL_PT7_POS)) /**< STOP_INTFL_PT7 Mask */

#define MXC_F_PTG_STOP_INTFL_PT8_POS                   8 /**< STOP_INTFL_PT8 Position */
#define MXC_F_PTG_STOP_INTFL_PT8                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTFL_PT8_POS)) /**< STOP_INTFL_PT8 Mask */

#define MXC_F_PTG_STOP_INTFL_PT9_POS                   9 /**< STOP_INTFL_PT9 Position */
#define MXC_F_PTG_STOP_INTFL_PT9                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTFL_PT9_POS)) /**< STOP_INTFL_PT9 Mask */

#define MXC_F_PTG_STOP_INTFL_PT10_POS                  10 /**< STOP_INTFL_PT10 Position */
#define MXC_F_PTG_STOP_INTFL_PT10                      ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTFL_PT10_POS)) /**< STOP_INTFL_PT10 Mask */

#define MXC_F_PTG_STOP_INTFL_PT11_POS                  11 /**< STOP_INTFL_PT11 Position */
#define MXC_F_PTG_STOP_INTFL_PT11                      ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTFL_PT11_POS)) /**< STOP_INTFL_PT11 Mask */

#define MXC_F_PTG_STOP_INTFL_PT12_POS                  12 /**< STOP_INTFL_PT12 Position */
#define MXC_F_PTG_STOP_INTFL_PT12                      ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTFL_PT12_POS)) /**< STOP_INTFL_PT12 Mask */

#define MXC_F_PTG_STOP_INTFL_PT13_POS                  13 /**< STOP_INTFL_PT13 Position */
#define MXC_F_PTG_STOP_INTFL_PT13                      ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTFL_PT13_POS)) /**< STOP_INTFL_PT13 Mask */

#define MXC_F_PTG_STOP_INTFL_PT14_POS                  14 /**< STOP_INTFL_PT14 Position */
#define MXC_F_PTG_STOP_INTFL_PT14                      ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTFL_PT14_POS)) /**< STOP_INTFL_PT14 Mask */

#define MXC_F_PTG_STOP_INTFL_PT15_POS                  15 /**< STOP_INTFL_PT15 Position */
#define MXC_F_PTG_STOP_INTFL_PT15                      ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTFL_PT15_POS)) /**< STOP_INTFL_PT15 Mask */

/**@} end of group PTG_STOP_INTFL_Register */

/**
 * @ingroup  ptg_registers
 * @defgroup PTG_STOP_INTEN PTG_STOP_INTEN
 * @brief    Pulse Train Interrupt Enable/Disable
 * @{
 */
#define MXC_F_PTG_STOP_INTEN_PT0_POS                   0 /**< STOP_INTEN_PT0 Position */
#define MXC_F_PTG_STOP_INTEN_PT0                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTEN_PT0_POS)) /**< STOP_INTEN_PT0 Mask */

#define MXC_F_PTG_STOP_INTEN_PT1_POS                   1 /**< STOP_INTEN_PT1 Position */
#define MXC_F_PTG_STOP_INTEN_PT1                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTEN_PT1_POS)) /**< STOP_INTEN_PT1 Mask */

#define MXC_F_PTG_STOP_INTEN_PT2_POS                   2 /**< STOP_INTEN_PT2 Position */
#define MXC_F_PTG_STOP_INTEN_PT2                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTEN_PT2_POS)) /**< STOP_INTEN_PT2 Mask */

#define MXC_F_PTG_STOP_INTEN_PT3_POS                   3 /**< STOP_INTEN_PT3 Position */
#define MXC_F_PTG_STOP_INTEN_PT3                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTEN_PT3_POS)) /**< STOP_INTEN_PT3 Mask */

#define MXC_F_PTG_STOP_INTEN_PT4_POS                   4 /**< STOP_INTEN_PT4 Position */
#define MXC_F_PTG_STOP_INTEN_PT4                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTEN_PT4_POS)) /**< STOP_INTEN_PT4 Mask */

#define MXC_F_PTG_STOP_INTEN_PT5_POS                   5 /**< STOP_INTEN_PT5 Position */
#define MXC_F_PTG_STOP_INTEN_PT5                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTEN_PT5_POS)) /**< STOP_INTEN_PT5 Mask */

#define MXC_F_PTG_STOP_INTEN_PT6_POS                   6 /**< STOP_INTEN_PT6 Position */
#define MXC_F_PTG_STOP_INTEN_PT6                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTEN_PT6_POS)) /**< STOP_INTEN_PT6 Mask */

#define MXC_F_PTG_STOP_INTEN_PT7_POS                   7 /**< STOP_INTEN_PT7 Position */
#define MXC_F_PTG_STOP_INTEN_PT7                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTEN_PT7_POS)) /**< STOP_INTEN_PT7 Mask */

#define MXC_F_PTG_STOP_INTEN_PT8_POS                   8 /**< STOP_INTEN_PT8 Position */
#define MXC_F_PTG_STOP_INTEN_PT8                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTEN_PT8_POS)) /**< STOP_INTEN_PT8 Mask */

#define MXC_F_PTG_STOP_INTEN_PT9_POS                   9 /**< STOP_INTEN_PT9 Position */
#define MXC_F_PTG_STOP_INTEN_PT9                       ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTEN_PT9_POS)) /**< STOP_INTEN_PT9 Mask */

#define MXC_F_PTG_STOP_INTEN_PT10_POS                  10 /**< STOP_INTEN_PT10 Position */
#define MXC_F_PTG_STOP_INTEN_PT10                      ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTEN_PT10_POS)) /**< STOP_INTEN_PT10 Mask */

#define MXC_F_PTG_STOP_INTEN_PT11_POS                  11 /**< STOP_INTEN_PT11 Position */
#define MXC_F_PTG_STOP_INTEN_PT11                      ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTEN_PT11_POS)) /**< STOP_INTEN_PT11 Mask */

#define MXC_F_PTG_STOP_INTEN_PT12_POS                  12 /**< STOP_INTEN_PT12 Position */
#define MXC_F_PTG_STOP_INTEN_PT12                      ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTEN_PT12_POS)) /**< STOP_INTEN_PT12 Mask */

#define MXC_F_PTG_STOP_INTEN_PT13_POS                  13 /**< STOP_INTEN_PT13 Position */
#define MXC_F_PTG_STOP_INTEN_PT13                      ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTEN_PT13_POS)) /**< STOP_INTEN_PT13 Mask */

#define MXC_F_PTG_STOP_INTEN_PT14_POS                  14 /**< STOP_INTEN_PT14 Position */
#define MXC_F_PTG_STOP_INTEN_PT14                      ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTEN_PT14_POS)) /**< STOP_INTEN_PT14 Mask */

#define MXC_F_PTG_STOP_INTEN_PT15_POS                  15 /**< STOP_INTEN_PT15 Position */
#define MXC_F_PTG_STOP_INTEN_PT15                      ((uint32_t)(0x1UL << MXC_F_PTG_STOP_INTEN_PT15_POS)) /**< STOP_INTEN_PT15 Mask */

/**@} end of group PTG_STOP_INTEN_Register */

/**
 * @ingroup  ptg_registers
 * @defgroup PTG_SAFE_EN PTG_SAFE_EN
 * @brief    Pulse Train Global Safe Enable.
 * @{
 */
#define MXC_F_PTG_SAFE_EN_PT0_POS                      0 /**< SAFE_EN_PT0 Position */
#define MXC_F_PTG_SAFE_EN_PT0                          ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_EN_PT0_POS)) /**< SAFE_EN_PT0 Mask */

#define MXC_F_PTG_SAFE_EN_PT1_POS                      1 /**< SAFE_EN_PT1 Position */
#define MXC_F_PTG_SAFE_EN_PT1                          ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_EN_PT1_POS)) /**< SAFE_EN_PT1 Mask */

#define MXC_F_PTG_SAFE_EN_PT2_POS                      2 /**< SAFE_EN_PT2 Position */
#define MXC_F_PTG_SAFE_EN_PT2                          ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_EN_PT2_POS)) /**< SAFE_EN_PT2 Mask */

#define MXC_F_PTG_SAFE_EN_PT3_POS                      3 /**< SAFE_EN_PT3 Position */
#define MXC_F_PTG_SAFE_EN_PT3                          ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_EN_PT3_POS)) /**< SAFE_EN_PT3 Mask */

#define MXC_F_PTG_SAFE_EN_PT4_POS                      4 /**< SAFE_EN_PT4 Position */
#define MXC_F_PTG_SAFE_EN_PT4                          ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_EN_PT4_POS)) /**< SAFE_EN_PT4 Mask */

#define MXC_F_PTG_SAFE_EN_PT5_POS                      5 /**< SAFE_EN_PT5 Position */
#define MXC_F_PTG_SAFE_EN_PT5                          ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_EN_PT5_POS)) /**< SAFE_EN_PT5 Mask */

#define MXC_F_PTG_SAFE_EN_PT6_POS                      6 /**< SAFE_EN_PT6 Position */
#define MXC_F_PTG_SAFE_EN_PT6                          ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_EN_PT6_POS)) /**< SAFE_EN_PT6 Mask */

#define MXC_F_PTG_SAFE_EN_PT7_POS                      7 /**< SAFE_EN_PT7 Position */
#define MXC_F_PTG_SAFE_EN_PT7                          ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_EN_PT7_POS)) /**< SAFE_EN_PT7 Mask */

#define MXC_F_PTG_SAFE_EN_PT8_POS                      8 /**< SAFE_EN_PT8 Position */
#define MXC_F_PTG_SAFE_EN_PT8                          ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_EN_PT8_POS)) /**< SAFE_EN_PT8 Mask */

#define MXC_F_PTG_SAFE_EN_PT9_POS                      9 /**< SAFE_EN_PT9 Position */
#define MXC_F_PTG_SAFE_EN_PT9                          ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_EN_PT9_POS)) /**< SAFE_EN_PT9 Mask */

#define MXC_F_PTG_SAFE_EN_PT10_POS                     10 /**< SAFE_EN_PT10 Position */
#define MXC_F_PTG_SAFE_EN_PT10                         ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_EN_PT10_POS)) /**< SAFE_EN_PT10 Mask */

#define MXC_F_PTG_SAFE_EN_PT11_POS                     11 /**< SAFE_EN_PT11 Position */
#define MXC_F_PTG_SAFE_EN_PT11                         ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_EN_PT11_POS)) /**< SAFE_EN_PT11 Mask */

#define MXC_F_PTG_SAFE_EN_PT12_POS                     12 /**< SAFE_EN_PT12 Position */
#define MXC_F_PTG_SAFE_EN_PT12                         ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_EN_PT12_POS)) /**< SAFE_EN_PT12 Mask */

#define MXC_F_PTG_SAFE_EN_PT13_POS                     13 /**< SAFE_EN_PT13 Position */
#define MXC_F_PTG_SAFE_EN_PT13                         ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_EN_PT13_POS)) /**< SAFE_EN_PT13 Mask */

#define MXC_F_PTG_SAFE_EN_PT14_POS                     14 /**< SAFE_EN_PT14 Position */
#define MXC_F_PTG_SAFE_EN_PT14                         ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_EN_PT14_POS)) /**< SAFE_EN_PT14 Mask */

#define MXC_F_PTG_SAFE_EN_PT15_POS                     15 /**< SAFE_EN_PT15 Position */
#define MXC_F_PTG_SAFE_EN_PT15                         ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_EN_PT15_POS)) /**< SAFE_EN_PT15 Mask */

/**@} end of group PTG_SAFE_EN_Register */

/**
 * @ingroup  ptg_registers
 * @defgroup PTG_SAFE_DIS PTG_SAFE_DIS
 * @brief    Pulse Train Global Safe Disable.
 * @{
 */
#define MXC_F_PTG_SAFE_DIS_PT0_POS                     0 /**< SAFE_DIS_PT0 Position */
#define MXC_F_PTG_SAFE_DIS_PT0                         ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_DIS_PT0_POS)) /**< SAFE_DIS_PT0 Mask */

#define MXC_F_PTG_SAFE_DIS_PT1_POS                     1 /**< SAFE_DIS_PT1 Position */
#define MXC_F_PTG_SAFE_DIS_PT1                         ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_DIS_PT1_POS)) /**< SAFE_DIS_PT1 Mask */

#define MXC_F_PTG_SAFE_DIS_PT2_POS                     2 /**< SAFE_DIS_PT2 Position */
#define MXC_F_PTG_SAFE_DIS_PT2                         ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_DIS_PT2_POS)) /**< SAFE_DIS_PT2 Mask */

#define MXC_F_PTG_SAFE_DIS_PT3_POS                     3 /**< SAFE_DIS_PT3 Position */
#define MXC_F_PTG_SAFE_DIS_PT3                         ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_DIS_PT3_POS)) /**< SAFE_DIS_PT3 Mask */

#define MXC_F_PTG_SAFE_DIS_PT4_POS                     4 /**< SAFE_DIS_PT4 Position */
#define MXC_F_PTG_SAFE_DIS_PT4                         ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_DIS_PT4_POS)) /**< SAFE_DIS_PT4 Mask */

#define MXC_F_PTG_SAFE_DIS_PT5_POS                     5 /**< SAFE_DIS_PT5 Position */
#define MXC_F_PTG_SAFE_DIS_PT5                         ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_DIS_PT5_POS)) /**< SAFE_DIS_PT5 Mask */

#define MXC_F_PTG_SAFE_DIS_PT6_POS                     6 /**< SAFE_DIS_PT6 Position */
#define MXC_F_PTG_SAFE_DIS_PT6                         ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_DIS_PT6_POS)) /**< SAFE_DIS_PT6 Mask */

#define MXC_F_PTG_SAFE_DIS_PT7_POS                     7 /**< SAFE_DIS_PT7 Position */
#define MXC_F_PTG_SAFE_DIS_PT7                         ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_DIS_PT7_POS)) /**< SAFE_DIS_PT7 Mask */

#define MXC_F_PTG_SAFE_DIS_PT8_POS                     8 /**< SAFE_DIS_PT8 Position */
#define MXC_F_PTG_SAFE_DIS_PT8                         ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_DIS_PT8_POS)) /**< SAFE_DIS_PT8 Mask */

#define MXC_F_PTG_SAFE_DIS_PT9_POS                     9 /**< SAFE_DIS_PT9 Position */
#define MXC_F_PTG_SAFE_DIS_PT9                         ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_DIS_PT9_POS)) /**< SAFE_DIS_PT9 Mask */

#define MXC_F_PTG_SAFE_DIS_PT10_POS                    10 /**< SAFE_DIS_PT10 Position */
#define MXC_F_PTG_SAFE_DIS_PT10                        ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_DIS_PT10_POS)) /**< SAFE_DIS_PT10 Mask */

#define MXC_F_PTG_SAFE_DIS_PT11_POS                    11 /**< SAFE_DIS_PT11 Position */
#define MXC_F_PTG_SAFE_DIS_PT11                        ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_DIS_PT11_POS)) /**< SAFE_DIS_PT11 Mask */

#define MXC_F_PTG_SAFE_DIS_PT12_POS                    12 /**< SAFE_DIS_PT12 Position */
#define MXC_F_PTG_SAFE_DIS_PT12                        ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_DIS_PT12_POS)) /**< SAFE_DIS_PT12 Mask */

#define MXC_F_PTG_SAFE_DIS_PT13_POS                    13 /**< SAFE_DIS_PT13 Position */
#define MXC_F_PTG_SAFE_DIS_PT13                        ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_DIS_PT13_POS)) /**< SAFE_DIS_PT13 Mask */

#define MXC_F_PTG_SAFE_DIS_PT14_POS                    14 /**< SAFE_DIS_PT14 Position */
#define MXC_F_PTG_SAFE_DIS_PT14                        ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_DIS_PT14_POS)) /**< SAFE_DIS_PT14 Mask */

#define MXC_F_PTG_SAFE_DIS_PT15_POS                    15 /**< SAFE_DIS_PT15 Position */
#define MXC_F_PTG_SAFE_DIS_PT15                        ((uint32_t)(0x1UL << MXC_F_PTG_SAFE_DIS_PT15_POS)) /**< SAFE_DIS_PT15 Mask */

/**@} end of group PTG_SAFE_DIS_Register */

/**
 * @ingroup  ptg_registers
 * @defgroup PTG_READY_INTFL PTG_READY_INTFL
 * @brief    Pulse Train Ready Interrupt Flags
 * @{
 */
#define MXC_F_PTG_READY_INTFL_PT0_POS                  0 /**< READY_INTFL_PT0 Position */
#define MXC_F_PTG_READY_INTFL_PT0                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTFL_PT0_POS)) /**< READY_INTFL_PT0 Mask */

#define MXC_F_PTG_READY_INTFL_PT1_POS                  1 /**< READY_INTFL_PT1 Position */
#define MXC_F_PTG_READY_INTFL_PT1                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTFL_PT1_POS)) /**< READY_INTFL_PT1 Mask */

#define MXC_F_PTG_READY_INTFL_PT2_POS                  2 /**< READY_INTFL_PT2 Position */
#define MXC_F_PTG_READY_INTFL_PT2                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTFL_PT2_POS)) /**< READY_INTFL_PT2 Mask */

#define MXC_F_PTG_READY_INTFL_PT3_POS                  3 /**< READY_INTFL_PT3 Position */
#define MXC_F_PTG_READY_INTFL_PT3                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTFL_PT3_POS)) /**< READY_INTFL_PT3 Mask */

#define MXC_F_PTG_READY_INTFL_PT4_POS                  4 /**< READY_INTFL_PT4 Position */
#define MXC_F_PTG_READY_INTFL_PT4                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTFL_PT4_POS)) /**< READY_INTFL_PT4 Mask */

#define MXC_F_PTG_READY_INTFL_PT5_POS                  5 /**< READY_INTFL_PT5 Position */
#define MXC_F_PTG_READY_INTFL_PT5                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTFL_PT5_POS)) /**< READY_INTFL_PT5 Mask */

#define MXC_F_PTG_READY_INTFL_PT6_POS                  6 /**< READY_INTFL_PT6 Position */
#define MXC_F_PTG_READY_INTFL_PT6                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTFL_PT6_POS)) /**< READY_INTFL_PT6 Mask */

#define MXC_F_PTG_READY_INTFL_PT7_POS                  7 /**< READY_INTFL_PT7 Position */
#define MXC_F_PTG_READY_INTFL_PT7                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTFL_PT7_POS)) /**< READY_INTFL_PT7 Mask */

#define MXC_F_PTG_READY_INTFL_PT8_POS                  8 /**< READY_INTFL_PT8 Position */
#define MXC_F_PTG_READY_INTFL_PT8                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTFL_PT8_POS)) /**< READY_INTFL_PT8 Mask */

#define MXC_F_PTG_READY_INTFL_PT9_POS                  9 /**< READY_INTFL_PT9 Position */
#define MXC_F_PTG_READY_INTFL_PT9                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTFL_PT9_POS)) /**< READY_INTFL_PT9 Mask */

#define MXC_F_PTG_READY_INTFL_PT10_POS                 10 /**< READY_INTFL_PT10 Position */
#define MXC_F_PTG_READY_INTFL_PT10                     ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTFL_PT10_POS)) /**< READY_INTFL_PT10 Mask */

#define MXC_F_PTG_READY_INTFL_PT11_POS                 11 /**< READY_INTFL_PT11 Position */
#define MXC_F_PTG_READY_INTFL_PT11                     ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTFL_PT11_POS)) /**< READY_INTFL_PT11 Mask */

#define MXC_F_PTG_READY_INTFL_PT12_POS                 12 /**< READY_INTFL_PT12 Position */
#define MXC_F_PTG_READY_INTFL_PT12                     ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTFL_PT12_POS)) /**< READY_INTFL_PT12 Mask */

#define MXC_F_PTG_READY_INTFL_PT13_POS                 13 /**< READY_INTFL_PT13 Position */
#define MXC_F_PTG_READY_INTFL_PT13                     ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTFL_PT13_POS)) /**< READY_INTFL_PT13 Mask */

#define MXC_F_PTG_READY_INTFL_PT14_POS                 14 /**< READY_INTFL_PT14 Position */
#define MXC_F_PTG_READY_INTFL_PT14                     ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTFL_PT14_POS)) /**< READY_INTFL_PT14 Mask */

#define MXC_F_PTG_READY_INTFL_PT15_POS                 15 /**< READY_INTFL_PT15 Position */
#define MXC_F_PTG_READY_INTFL_PT15                     ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTFL_PT15_POS)) /**< READY_INTFL_PT15 Mask */

/**@} end of group PTG_READY_INTFL_Register */

/**
 * @ingroup  ptg_registers
 * @defgroup PTG_READY_INTEN PTG_READY_INTEN
 * @brief    Pulse Train Ready Interrupt Enable/Disable
 * @{
 */
#define MXC_F_PTG_READY_INTEN_PT0_POS                  0 /**< READY_INTEN_PT0 Position */
#define MXC_F_PTG_READY_INTEN_PT0                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTEN_PT0_POS)) /**< READY_INTEN_PT0 Mask */

#define MXC_F_PTG_READY_INTEN_PT1_POS                  1 /**< READY_INTEN_PT1 Position */
#define MXC_F_PTG_READY_INTEN_PT1                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTEN_PT1_POS)) /**< READY_INTEN_PT1 Mask */

#define MXC_F_PTG_READY_INTEN_PT2_POS                  2 /**< READY_INTEN_PT2 Position */
#define MXC_F_PTG_READY_INTEN_PT2                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTEN_PT2_POS)) /**< READY_INTEN_PT2 Mask */

#define MXC_F_PTG_READY_INTEN_PT3_POS                  3 /**< READY_INTEN_PT3 Position */
#define MXC_F_PTG_READY_INTEN_PT3                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTEN_PT3_POS)) /**< READY_INTEN_PT3 Mask */

#define MXC_F_PTG_READY_INTEN_PT4_POS                  4 /**< READY_INTEN_PT4 Position */
#define MXC_F_PTG_READY_INTEN_PT4                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTEN_PT4_POS)) /**< READY_INTEN_PT4 Mask */

#define MXC_F_PTG_READY_INTEN_PT5_POS                  5 /**< READY_INTEN_PT5 Position */
#define MXC_F_PTG_READY_INTEN_PT5                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTEN_PT5_POS)) /**< READY_INTEN_PT5 Mask */

#define MXC_F_PTG_READY_INTEN_PT6_POS                  6 /**< READY_INTEN_PT6 Position */
#define MXC_F_PTG_READY_INTEN_PT6                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTEN_PT6_POS)) /**< READY_INTEN_PT6 Mask */

#define MXC_F_PTG_READY_INTEN_PT7_POS                  7 /**< READY_INTEN_PT7 Position */
#define MXC_F_PTG_READY_INTEN_PT7                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTEN_PT7_POS)) /**< READY_INTEN_PT7 Mask */

#define MXC_F_PTG_READY_INTEN_PT8_POS                  8 /**< READY_INTEN_PT8 Position */
#define MXC_F_PTG_READY_INTEN_PT8                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTEN_PT8_POS)) /**< READY_INTEN_PT8 Mask */

#define MXC_F_PTG_READY_INTEN_PT9_POS                  9 /**< READY_INTEN_PT9 Position */
#define MXC_F_PTG_READY_INTEN_PT9                      ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTEN_PT9_POS)) /**< READY_INTEN_PT9 Mask */

#define MXC_F_PTG_READY_INTEN_PT10_POS                 10 /**< READY_INTEN_PT10 Position */
#define MXC_F_PTG_READY_INTEN_PT10                     ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTEN_PT10_POS)) /**< READY_INTEN_PT10 Mask */

#define MXC_F_PTG_READY_INTEN_PT11_POS                 11 /**< READY_INTEN_PT11 Position */
#define MXC_F_PTG_READY_INTEN_PT11                     ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTEN_PT11_POS)) /**< READY_INTEN_PT11 Mask */

#define MXC_F_PTG_READY_INTEN_PT12_POS                 12 /**< READY_INTEN_PT12 Position */
#define MXC_F_PTG_READY_INTEN_PT12                     ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTEN_PT12_POS)) /**< READY_INTEN_PT12 Mask */

#define MXC_F_PTG_READY_INTEN_PT13_POS                 13 /**< READY_INTEN_PT13 Position */
#define MXC_F_PTG_READY_INTEN_PT13                     ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTEN_PT13_POS)) /**< READY_INTEN_PT13 Mask */

#define MXC_F_PTG_READY_INTEN_PT14_POS                 14 /**< READY_INTEN_PT14 Position */
#define MXC_F_PTG_READY_INTEN_PT14                     ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTEN_PT14_POS)) /**< READY_INTEN_PT14 Mask */

#define MXC_F_PTG_READY_INTEN_PT15_POS                 15 /**< READY_INTEN_PT15 Position */
#define MXC_F_PTG_READY_INTEN_PT15                     ((uint32_t)(0x1UL << MXC_F_PTG_READY_INTEN_PT15_POS)) /**< READY_INTEN_PT15 Mask */

/**@} end of group PTG_READY_INTEN_Register */

#ifdef __cplusplus
}
#endif

#endif // LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32690_INCLUDE_PTG_REGS_H_
