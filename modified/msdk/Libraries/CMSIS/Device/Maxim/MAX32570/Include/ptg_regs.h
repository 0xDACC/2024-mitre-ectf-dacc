/**
 * @file    ptg_regs.h
 * @brief   Registers, Bit Masks and Bit Positions for the PTG Peripheral Module.
 * @note    This file is @generated.
 */

/******************************************************************************
 * Copyright (C) 2022 Maxim Integrated Products, Inc., All rights Reserved.
 * 
 * This software is protected by copyright laws of the United States and
 * of foreign countries. This material may also be protected by patent laws
 * and technology transfer regulations of the United States and of foreign
 * countries. This software is furnished under a license agreement and/or a
 * nondisclosure agreement and may only be used or reproduced in accordance
 * with the terms of those agreements. Dissemination of this information to
 * any party or parties not specified in the license agreement and/or
 * nondisclosure agreement is expressly prohibited.
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

#ifndef LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32570_INCLUDE_PTG_REGS_H_
#define LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32570_INCLUDE_PTG_REGS_H_

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
    __IO uint32_t intfl;                /**< <tt>\b 0x0008:</tt> PTG INTFL Register */
    __IO uint32_t inten;                /**< <tt>\b 0x000C:</tt> PTG INTEN Register */
    __O  uint32_t safe_en;              /**< <tt>\b 0x0010:</tt> PTG SAFE_EN Register */
    __O  uint32_t safe_dis;             /**< <tt>\b 0x0014:</tt> PTG SAFE_DIS Register */
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
#define MXC_R_PTG_INTFL                    ((uint32_t)0x00000008UL) /**< Offset from PTG Base Address: <tt> 0x0008</tt> */
#define MXC_R_PTG_INTEN                    ((uint32_t)0x0000000CUL) /**< Offset from PTG Base Address: <tt> 0x000C</tt> */
#define MXC_R_PTG_SAFE_EN                  ((uint32_t)0x00000010UL) /**< Offset from PTG Base Address: <tt> 0x0010</tt> */
#define MXC_R_PTG_SAFE_DIS                 ((uint32_t)0x00000014UL) /**< Offset from PTG Base Address: <tt> 0x0014</tt> */
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

/**@} end of group PTG_RESYNC_Register */

/**
 * @ingroup  ptg_registers
 * @defgroup PTG_INTFL PTG_INTFL
 * @brief    Pulse Train Interrupt Flags
 * @{
 */
#define MXC_F_PTG_INTFL_PT0_POS                        0 /**< INTFL_PT0 Position */
#define MXC_F_PTG_INTFL_PT0                            ((uint32_t)(0x1UL << MXC_F_PTG_INTFL_PT0_POS)) /**< INTFL_PT0 Mask */

#define MXC_F_PTG_INTFL_PT1_POS                        1 /**< INTFL_PT1 Position */
#define MXC_F_PTG_INTFL_PT1                            ((uint32_t)(0x1UL << MXC_F_PTG_INTFL_PT1_POS)) /**< INTFL_PT1 Mask */

#define MXC_F_PTG_INTFL_PT2_POS                        2 /**< INTFL_PT2 Position */
#define MXC_F_PTG_INTFL_PT2                            ((uint32_t)(0x1UL << MXC_F_PTG_INTFL_PT2_POS)) /**< INTFL_PT2 Mask */

#define MXC_F_PTG_INTFL_PT3_POS                        3 /**< INTFL_PT3 Position */
#define MXC_F_PTG_INTFL_PT3                            ((uint32_t)(0x1UL << MXC_F_PTG_INTFL_PT3_POS)) /**< INTFL_PT3 Mask */

#define MXC_F_PTG_INTFL_PT4_POS                        4 /**< INTFL_PT4 Position */
#define MXC_F_PTG_INTFL_PT4                            ((uint32_t)(0x1UL << MXC_F_PTG_INTFL_PT4_POS)) /**< INTFL_PT4 Mask */

#define MXC_F_PTG_INTFL_PT5_POS                        5 /**< INTFL_PT5 Position */
#define MXC_F_PTG_INTFL_PT5                            ((uint32_t)(0x1UL << MXC_F_PTG_INTFL_PT5_POS)) /**< INTFL_PT5 Mask */

#define MXC_F_PTG_INTFL_PT6_POS                        6 /**< INTFL_PT6 Position */
#define MXC_F_PTG_INTFL_PT6                            ((uint32_t)(0x1UL << MXC_F_PTG_INTFL_PT6_POS)) /**< INTFL_PT6 Mask */

#define MXC_F_PTG_INTFL_PT7_POS                        7 /**< INTFL_PT7 Position */
#define MXC_F_PTG_INTFL_PT7                            ((uint32_t)(0x1UL << MXC_F_PTG_INTFL_PT7_POS)) /**< INTFL_PT7 Mask */

/**@} end of group PTG_INTFL_Register */

/**
 * @ingroup  ptg_registers
 * @defgroup PTG_INTEN PTG_INTEN
 * @brief    Pulse Train Interrupt Enable/Disable
 * @{
 */
#define MXC_F_PTG_INTEN_PT0_POS                        0 /**< INTEN_PT0 Position */
#define MXC_F_PTG_INTEN_PT0                            ((uint32_t)(0x1UL << MXC_F_PTG_INTEN_PT0_POS)) /**< INTEN_PT0 Mask */

#define MXC_F_PTG_INTEN_PT1_POS                        1 /**< INTEN_PT1 Position */
#define MXC_F_PTG_INTEN_PT1                            ((uint32_t)(0x1UL << MXC_F_PTG_INTEN_PT1_POS)) /**< INTEN_PT1 Mask */

#define MXC_F_PTG_INTEN_PT2_POS                        2 /**< INTEN_PT2 Position */
#define MXC_F_PTG_INTEN_PT2                            ((uint32_t)(0x1UL << MXC_F_PTG_INTEN_PT2_POS)) /**< INTEN_PT2 Mask */

#define MXC_F_PTG_INTEN_PT3_POS                        3 /**< INTEN_PT3 Position */
#define MXC_F_PTG_INTEN_PT3                            ((uint32_t)(0x1UL << MXC_F_PTG_INTEN_PT3_POS)) /**< INTEN_PT3 Mask */

#define MXC_F_PTG_INTEN_PT4_POS                        4 /**< INTEN_PT4 Position */
#define MXC_F_PTG_INTEN_PT4                            ((uint32_t)(0x1UL << MXC_F_PTG_INTEN_PT4_POS)) /**< INTEN_PT4 Mask */

#define MXC_F_PTG_INTEN_PT5_POS                        5 /**< INTEN_PT5 Position */
#define MXC_F_PTG_INTEN_PT5                            ((uint32_t)(0x1UL << MXC_F_PTG_INTEN_PT5_POS)) /**< INTEN_PT5 Mask */

#define MXC_F_PTG_INTEN_PT6_POS                        6 /**< INTEN_PT6 Position */
#define MXC_F_PTG_INTEN_PT6                            ((uint32_t)(0x1UL << MXC_F_PTG_INTEN_PT6_POS)) /**< INTEN_PT6 Mask */

#define MXC_F_PTG_INTEN_PT7_POS                        7 /**< INTEN_PT7 Position */
#define MXC_F_PTG_INTEN_PT7                            ((uint32_t)(0x1UL << MXC_F_PTG_INTEN_PT7_POS)) /**< INTEN_PT7 Mask */

/**@} end of group PTG_INTEN_Register */

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

/**@} end of group PTG_SAFE_DIS_Register */

#ifdef __cplusplus
}
#endif

#endif // LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32570_INCLUDE_PTG_REGS_H_
