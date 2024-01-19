/**
 * @file    fcr_regs.h
 * @brief   Registers, Bit Masks and Bit Positions for the FCR Peripheral Module.
 * @note    This file is @generated.
 * @ingroup fcr_registers
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

#ifndef LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32655_INCLUDE_FCR_REGS_H_
#define LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32655_INCLUDE_FCR_REGS_H_

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
 * @ingroup     fcr
 * @defgroup    fcr_registers FCR_Registers
 * @brief       Registers, Bit Masks and Bit Positions for the FCR Peripheral Module.
 * @details     Function Control Register.
 */

/**
 * @ingroup fcr_registers
 * Structure type to access the FCR Registers.
 */
typedef struct {
    __IO uint32_t fctrl0;               /**< <tt>\b 0x00:</tt> FCR FCTRL0 Register */
    __IO uint32_t autocal0;             /**< <tt>\b 0x04:</tt> FCR AUTOCAL0 Register */
    __IO uint32_t autocal1;             /**< <tt>\b 0x08:</tt> FCR AUTOCAL1 Register */
    __IO uint32_t autocal2;             /**< <tt>\b 0x0C:</tt> FCR AUTOCAL2 Register */
    __IO uint32_t urvbootaddr;          /**< <tt>\b 0x10:</tt> FCR URVBOOTADDR Register */
    __IO uint32_t urvctrl;              /**< <tt>\b 0x14:</tt> FCR URVCTRL Register */
    __IO uint32_t erfoks;               /**< <tt>\b 0x18:</tt> FCR ERFOKS Register */
    __IO uint32_t erfo_intfl;           /**< <tt>\b 0x1C:</tt> FCR ERFO_INTFL Register */
    __IO uint32_t erfo_inten;           /**< <tt>\b 0x20:</tt> FCR ERFO_INTEN Register */
} mxc_fcr_regs_t;

/* Register offsets for module FCR */
/**
 * @ingroup    fcr_registers
 * @defgroup   FCR_Register_Offsets Register Offsets
 * @brief      FCR Peripheral Register Offsets from the FCR Base Peripheral Address.
 * @{
 */
#define MXC_R_FCR_FCTRL0                   ((uint32_t)0x00000000UL) /**< Offset from FCR Base Address: <tt> 0x0000</tt> */
#define MXC_R_FCR_AUTOCAL0                 ((uint32_t)0x00000004UL) /**< Offset from FCR Base Address: <tt> 0x0004</tt> */
#define MXC_R_FCR_AUTOCAL1                 ((uint32_t)0x00000008UL) /**< Offset from FCR Base Address: <tt> 0x0008</tt> */
#define MXC_R_FCR_AUTOCAL2                 ((uint32_t)0x0000000CUL) /**< Offset from FCR Base Address: <tt> 0x000C</tt> */
#define MXC_R_FCR_URVBOOTADDR              ((uint32_t)0x00000010UL) /**< Offset from FCR Base Address: <tt> 0x0010</tt> */
#define MXC_R_FCR_URVCTRL                  ((uint32_t)0x00000014UL) /**< Offset from FCR Base Address: <tt> 0x0014</tt> */
#define MXC_R_FCR_ERFOKS                   ((uint32_t)0x00000018UL) /**< Offset from FCR Base Address: <tt> 0x0018</tt> */
#define MXC_R_FCR_ERFO_INTFL               ((uint32_t)0x0000001CUL) /**< Offset from FCR Base Address: <tt> 0x001C</tt> */
#define MXC_R_FCR_ERFO_INTEN               ((uint32_t)0x00000020UL) /**< Offset from FCR Base Address: <tt> 0x0020</tt> */
/**@} end of group fcr_registers */

/**
 * @ingroup  fcr_registers
 * @defgroup FCR_FCTRL0 FCR_FCTRL0
 * @brief    Function Control 0.
 * @{
 */
#define MXC_F_FCR_FCTRL0_I2C0DGEN0_POS                 20 /**< FCTRL0_I2C0DGEN0 Position */
#define MXC_F_FCR_FCTRL0_I2C0DGEN0                     ((uint32_t)(0x1UL << MXC_F_FCR_FCTRL0_I2C0DGEN0_POS)) /**< FCTRL0_I2C0DGEN0 Mask */

#define MXC_F_FCR_FCTRL0_I2C0DGEN1_POS                 21 /**< FCTRL0_I2C0DGEN1 Position */
#define MXC_F_FCR_FCTRL0_I2C0DGEN1                     ((uint32_t)(0x1UL << MXC_F_FCR_FCTRL0_I2C0DGEN1_POS)) /**< FCTRL0_I2C0DGEN1 Mask */

#define MXC_F_FCR_FCTRL0_I2C1DGEN0_POS                 22 /**< FCTRL0_I2C1DGEN0 Position */
#define MXC_F_FCR_FCTRL0_I2C1DGEN0                     ((uint32_t)(0x1UL << MXC_F_FCR_FCTRL0_I2C1DGEN0_POS)) /**< FCTRL0_I2C1DGEN0 Mask */

#define MXC_F_FCR_FCTRL0_I2C1DGEN1_POS                 23 /**< FCTRL0_I2C1DGEN1 Position */
#define MXC_F_FCR_FCTRL0_I2C1DGEN1                     ((uint32_t)(0x1UL << MXC_F_FCR_FCTRL0_I2C1DGEN1_POS)) /**< FCTRL0_I2C1DGEN1 Mask */

#define MXC_F_FCR_FCTRL0_I2C2DGEN0_POS                 24 /**< FCTRL0_I2C2DGEN0 Position */
#define MXC_F_FCR_FCTRL0_I2C2DGEN0                     ((uint32_t)(0x1UL << MXC_F_FCR_FCTRL0_I2C2DGEN0_POS)) /**< FCTRL0_I2C2DGEN0 Mask */

#define MXC_F_FCR_FCTRL0_I2C2DGEN1_POS                 25 /**< FCTRL0_I2C2DGEN1 Position */
#define MXC_F_FCR_FCTRL0_I2C2DGEN1                     ((uint32_t)(0x1UL << MXC_F_FCR_FCTRL0_I2C2DGEN1_POS)) /**< FCTRL0_I2C2DGEN1 Mask */

/**@} end of group FCR_FCTRL0_Register */

/**
 * @ingroup  fcr_registers
 * @defgroup FCR_AUTOCAL0 FCR_AUTOCAL0
 * @brief    Automatic Calibration 0.
 * @{
 */
#define MXC_F_FCR_AUTOCAL0_ACEN_POS                    0 /**< AUTOCAL0_ACEN Position */
#define MXC_F_FCR_AUTOCAL0_ACEN                        ((uint32_t)(0x1UL << MXC_F_FCR_AUTOCAL0_ACEN_POS)) /**< AUTOCAL0_ACEN Mask */

#define MXC_F_FCR_AUTOCAL0_ACRUN_POS                   1 /**< AUTOCAL0_ACRUN Position */
#define MXC_F_FCR_AUTOCAL0_ACRUN                       ((uint32_t)(0x1UL << MXC_F_FCR_AUTOCAL0_ACRUN_POS)) /**< AUTOCAL0_ACRUN Mask */

#define MXC_F_FCR_AUTOCAL0_LDTRM_POS                   2 /**< AUTOCAL0_LDTRM Position */
#define MXC_F_FCR_AUTOCAL0_LDTRM                       ((uint32_t)(0x1UL << MXC_F_FCR_AUTOCAL0_LDTRM_POS)) /**< AUTOCAL0_LDTRM Mask */

#define MXC_F_FCR_AUTOCAL0_GAININV_POS                 3 /**< AUTOCAL0_GAININV Position */
#define MXC_F_FCR_AUTOCAL0_GAININV                     ((uint32_t)(0x1UL << MXC_F_FCR_AUTOCAL0_GAININV_POS)) /**< AUTOCAL0_GAININV Mask */

#define MXC_F_FCR_AUTOCAL0_ATOMIC_POS                  4 /**< AUTOCAL0_ATOMIC Position */
#define MXC_F_FCR_AUTOCAL0_ATOMIC                      ((uint32_t)(0x1UL << MXC_F_FCR_AUTOCAL0_ATOMIC_POS)) /**< AUTOCAL0_ATOMIC Mask */

#define MXC_F_FCR_AUTOCAL0_MU_POS                      8 /**< AUTOCAL0_MU Position */
#define MXC_F_FCR_AUTOCAL0_MU                          ((uint32_t)(0xFFFUL << MXC_F_FCR_AUTOCAL0_MU_POS)) /**< AUTOCAL0_MU Mask */

#define MXC_F_FCR_AUTOCAL0_HIRC96MACTMROUT_POS         23 /**< AUTOCAL0_HIRC96MACTMROUT Position */
#define MXC_F_FCR_AUTOCAL0_HIRC96MACTMROUT             ((uint32_t)(0x1FFUL << MXC_F_FCR_AUTOCAL0_HIRC96MACTMROUT_POS)) /**< AUTOCAL0_HIRC96MACTMROUT Mask */

/**@} end of group FCR_AUTOCAL0_Register */

/**
 * @ingroup  fcr_registers
 * @defgroup FCR_AUTOCAL1 FCR_AUTOCAL1
 * @brief    Automatic Calibration 1.
 * @{
 */
#define MXC_F_FCR_AUTOCAL1_INITTRM_POS                 0 /**< AUTOCAL1_INITTRM Position */
#define MXC_F_FCR_AUTOCAL1_INITTRM                     ((uint32_t)(0x1FFUL << MXC_F_FCR_AUTOCAL1_INITTRM_POS)) /**< AUTOCAL1_INITTRM Mask */

/**@} end of group FCR_AUTOCAL1_Register */

/**
 * @ingroup  fcr_registers
 * @defgroup FCR_AUTOCAL2 FCR_AUTOCAL2
 * @brief    Automatic Calibration 2
 * @{
 */
#define MXC_F_FCR_AUTOCAL2_DONECNT_POS                 0 /**< AUTOCAL2_DONECNT Position */
#define MXC_F_FCR_AUTOCAL2_DONECNT                     ((uint32_t)(0xFFUL << MXC_F_FCR_AUTOCAL2_DONECNT_POS)) /**< AUTOCAL2_DONECNT Mask */

#define MXC_F_FCR_AUTOCAL2_ACDIV_POS                   8 /**< AUTOCAL2_ACDIV Position */
#define MXC_F_FCR_AUTOCAL2_ACDIV                       ((uint32_t)(0x1FFFUL << MXC_F_FCR_AUTOCAL2_ACDIV_POS)) /**< AUTOCAL2_ACDIV Mask */

/**@} end of group FCR_AUTOCAL2_Register */

/**
 * @ingroup  fcr_registers
 * @defgroup FCR_URVCTRL FCR_URVCTRL
 * @brief    RISC-V Control Register.
 * @{
 */
#define MXC_F_FCR_URVCTRL_MEMSEL_POS                   0 /**< URVCTRL_MEMSEL Position */
#define MXC_F_FCR_URVCTRL_MEMSEL                       ((uint32_t)(0x1UL << MXC_F_FCR_URVCTRL_MEMSEL_POS)) /**< URVCTRL_MEMSEL Mask */

#define MXC_F_FCR_URVCTRL_IFLUSHEN_POS                 1 /**< URVCTRL_IFLUSHEN Position */
#define MXC_F_FCR_URVCTRL_IFLUSHEN                     ((uint32_t)(0x1UL << MXC_F_FCR_URVCTRL_IFLUSHEN_POS)) /**< URVCTRL_IFLUSHEN Mask */

/**@} end of group FCR_URVCTRL_Register */

/**
 * @ingroup  fcr_registers
 * @defgroup FCR_ERFOKS FCR_ERFOKS
 * @brief    ERFO Kick Start Register.
 * @{
 */
#define MXC_F_FCR_ERFOKS_KSERFO_CNT_POS                0 /**< ERFOKS_KSERFO_CNT Position */
#define MXC_F_FCR_ERFOKS_KSERFO_CNT                    ((uint32_t)(0x7FUL << MXC_F_FCR_ERFOKS_KSERFO_CNT_POS)) /**< ERFOKS_KSERFO_CNT Mask */

#define MXC_F_FCR_ERFOKS_KSERFO_EN_POS                 7 /**< ERFOKS_KSERFO_EN Position */
#define MXC_F_FCR_ERFOKS_KSERFO_EN                     ((uint32_t)(0x1UL << MXC_F_FCR_ERFOKS_KSERFO_EN_POS)) /**< ERFOKS_KSERFO_EN Mask */

#define MXC_F_FCR_ERFOKS_KSERFODRIVER_POS              8 /**< ERFOKS_KSERFODRIVER Position */
#define MXC_F_FCR_ERFOKS_KSERFODRIVER                  ((uint32_t)(0x7UL << MXC_F_FCR_ERFOKS_KSERFODRIVER_POS)) /**< ERFOKS_KSERFODRIVER Mask */

#define MXC_F_FCR_ERFOKS_KSERFO2X_POS                  11 /**< ERFOKS_KSERFO2X Position */
#define MXC_F_FCR_ERFOKS_KSERFO2X                      ((uint32_t)(0x1UL << MXC_F_FCR_ERFOKS_KSERFO2X_POS)) /**< ERFOKS_KSERFO2X Mask */

#define MXC_F_FCR_ERFOKS_KSCLKSEL_POS                  12 /**< ERFOKS_KSCLKSEL Position */
#define MXC_F_FCR_ERFOKS_KSCLKSEL                      ((uint32_t)(0x3UL << MXC_F_FCR_ERFOKS_KSCLKSEL_POS)) /**< ERFOKS_KSCLKSEL Mask */
#define MXC_V_FCR_ERFOKS_KSCLKSEL_ISO                  ((uint32_t)0x2UL) /**< ERFOKS_KSCLKSEL_ISO Value */
#define MXC_S_FCR_ERFOKS_KSCLKSEL_ISO                  (MXC_V_FCR_ERFOKS_KSCLKSEL_ISO << MXC_F_FCR_ERFOKS_KSCLKSEL_POS) /**< ERFOKS_KSCLKSEL_ISO Setting */
#define MXC_V_FCR_ERFOKS_KSCLKSEL_IPO                  ((uint32_t)0x3UL) /**< ERFOKS_KSCLKSEL_IPO Value */
#define MXC_S_FCR_ERFOKS_KSCLKSEL_IPO                  (MXC_V_FCR_ERFOKS_KSCLKSEL_IPO << MXC_F_FCR_ERFOKS_KSCLKSEL_POS) /**< ERFOKS_KSCLKSEL_IPO Setting */

/**@} end of group FCR_ERFOKS_Register */

/**
 * @ingroup  fcr_registers
 * @defgroup FCR_ERFO_INTFL FCR_ERFO_INTFL
 * @brief    ERFO Ready Interrupt Flag register.
 * @{
 */
#define MXC_F_FCR_ERFO_INTFL_RDY_POS                   0 /**< ERFO_INTFL_RDY Position */
#define MXC_F_FCR_ERFO_INTFL_RDY                       ((uint32_t)(0x1UL << MXC_F_FCR_ERFO_INTFL_RDY_POS)) /**< ERFO_INTFL_RDY Mask */

/**@} end of group FCR_ERFO_INTFL_Register */

/**
 * @ingroup  fcr_registers
 * @defgroup FCR_ERFO_INTEN FCR_ERFO_INTEN
 * @brief    ERFO Ready Interrupt Enable register.
 * @{
 */
#define MXC_F_FCR_ERFO_INTEN_RDY_POS                   0 /**< ERFO_INTEN_RDY Position */
#define MXC_F_FCR_ERFO_INTEN_RDY                       ((uint32_t)(0x1UL << MXC_F_FCR_ERFO_INTEN_RDY_POS)) /**< ERFO_INTEN_RDY Mask */

/**@} end of group FCR_ERFO_INTEN_Register */

#ifdef __cplusplus
}
#endif

#endif // LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32655_INCLUDE_FCR_REGS_H_
