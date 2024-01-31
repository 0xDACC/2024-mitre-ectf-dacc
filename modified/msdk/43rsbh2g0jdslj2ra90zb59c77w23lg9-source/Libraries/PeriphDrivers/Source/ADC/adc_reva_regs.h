/**
 * @file    adc_reva_regs.h
 * @brief   Registers, Bit Masks and Bit Positions for the ADC_REVA Peripheral Module.
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

#ifndef _ADC_REVA_REGS_H_
#define _ADC_REVA_REGS_H_

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
 * @ingroup     adc_reva
 * @defgroup    adc_reva_registers ADC_REVA_Registers
 * @brief       Registers, Bit Masks and Bit Positions for the ADC_REVA Peripheral Module.
 * @details 10-bit Analog to Digital Converter
 */

/**
 * @ingroup adc_reva_registers
 * Structure type to access the ADC_REVA Registers.
 */
typedef struct {
    __IO uint32_t ctrl;                 /**< <tt>\b 0x0000:</tt> ADC_REVA CTRL Register */
    __IO uint32_t status;               /**< <tt>\b 0x0004:</tt> ADC_REVA STATUS Register */
    __IO uint32_t data;                 /**< <tt>\b 0x0008:</tt> ADC_REVA DATA Register */
    __IO uint32_t intr;                 /**< <tt>\b 0x000C:</tt> ADC_REVA INTR Register */
    __IO uint32_t limit[4];             /**< <tt>\b 0x0010:</tt> ADC_REVA LIMIT Register */
} mxc_adc_reva_regs_t;

/* Register offsets for module ADC_REVA */
/**
 * @ingroup    adc_reva_registers
 * @defgroup   ADC_REVA_Register_Offsets Register Offsets
 * @brief      ADC_REVA Peripheral Register Offsets from the ADC_REVA Base Peripheral Address.
 * @{
 */
 #define MXC_R_ADC_REVA_CTRL                ((uint32_t)0x00000000UL) /**< Offset from ADC_REVA Base Address: <tt> 0x0000</tt> */ 
 #define MXC_R_ADC_REVA_STATUS              ((uint32_t)0x00000004UL) /**< Offset from ADC_REVA Base Address: <tt> 0x0004</tt> */ 
 #define MXC_R_ADC_REVA_DATA                ((uint32_t)0x00000008UL) /**< Offset from ADC_REVA Base Address: <tt> 0x0008</tt> */ 
 #define MXC_R_ADC_REVA_INTR                ((uint32_t)0x0000000CUL) /**< Offset from ADC_REVA Base Address: <tt> 0x000C</tt> */ 
 #define MXC_R_ADC_REVA_LIMIT               ((uint32_t)0x00000010UL) /**< Offset from ADC_REVA Base Address: <tt> 0x0010</tt> */ 
/**@} end of group adc_reva_registers */

/**
 * @ingroup  adc_reva_registers
 * @defgroup ADC_REVA_CTRL ADC_REVA_CTRL
 * @brief    ADC Control
 * @{
 */
 #define MXC_F_ADC_REVA_CTRL_START_POS                  0 /**< CTRL_START Position */
 #define MXC_F_ADC_REVA_CTRL_START                      ((uint32_t)(0x1UL << MXC_F_ADC_REVA_CTRL_START_POS)) /**< CTRL_START Mask */

 #define MXC_F_ADC_REVA_CTRL_PWR_POS                    1 /**< CTRL_PWR Position */
 #define MXC_F_ADC_REVA_CTRL_PWR                        ((uint32_t)(0x1UL << MXC_F_ADC_REVA_CTRL_PWR_POS)) /**< CTRL_PWR Mask */

 #define MXC_F_ADC_REVA_CTRL_REFBUF_PWR_POS             3 /**< CTRL_REFBUF_PWR Position */
 #define MXC_F_ADC_REVA_CTRL_REFBUF_PWR                 ((uint32_t)(0x1UL << MXC_F_ADC_REVA_CTRL_REFBUF_PWR_POS)) /**< CTRL_REFBUF_PWR Mask */

 #define MXC_F_ADC_REVA_CTRL_REF_SEL_POS                4 /**< CTRL_REF_SEL Position */
 #define MXC_F_ADC_REVA_CTRL_REF_SEL                    ((uint32_t)(0x1UL << MXC_F_ADC_REVA_CTRL_REF_SEL_POS)) /**< CTRL_REF_SEL Mask */

 #define MXC_F_ADC_REVA_CTRL_REF_SCALE_POS              8 /**< CTRL_REF_SCALE Position */
 #define MXC_F_ADC_REVA_CTRL_REF_SCALE                  ((uint32_t)(0x1UL << MXC_F_ADC_REVA_CTRL_REF_SCALE_POS)) /**< CTRL_REF_SCALE Mask */

 #define MXC_F_ADC_REVA_CTRL_SCALE_POS                  9 /**< CTRL_SCALE Position */
 #define MXC_F_ADC_REVA_CTRL_SCALE                      ((uint32_t)(0x1UL << MXC_F_ADC_REVA_CTRL_SCALE_POS)) /**< CTRL_SCALE Mask */

 #define MXC_F_ADC_REVA_CTRL_CLK_EN_POS                 11 /**< CTRL_CLK_EN Position */
 #define MXC_F_ADC_REVA_CTRL_CLK_EN                     ((uint32_t)(0x1UL << MXC_F_ADC_REVA_CTRL_CLK_EN_POS)) /**< CTRL_CLK_EN Mask */

 #define MXC_F_ADC_REVA_CTRL_CH_SEL_POS                 12 /**< CTRL_CH_SEL Position */
 #define MXC_F_ADC_REVA_CTRL_CH_SEL                     ((uint32_t)(0x1FUL << MXC_F_ADC_REVA_CTRL_CH_SEL_POS)) /**< CTRL_CH_SEL Mask */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_AIN0                ((uint32_t)0x0UL) /**< CTRL_CH_SEL_AIN0 Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_AIN0                (MXC_V_ADC_REVA_CTRL_CH_SEL_AIN0 << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_AIN0 Setting */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_AIN1                ((uint32_t)0x1UL) /**< CTRL_CH_SEL_AIN1 Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_AIN1                (MXC_V_ADC_REVA_CTRL_CH_SEL_AIN1 << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_AIN1 Setting */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_AIN2                ((uint32_t)0x2UL) /**< CTRL_CH_SEL_AIN2 Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_AIN2                (MXC_V_ADC_REVA_CTRL_CH_SEL_AIN2 << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_AIN2 Setting */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_AIN3                ((uint32_t)0x3UL) /**< CTRL_CH_SEL_AIN3 Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_AIN3                (MXC_V_ADC_REVA_CTRL_CH_SEL_AIN3 << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_AIN3 Setting */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_AIN4                ((uint32_t)0x4UL) /**< CTRL_CH_SEL_AIN4 Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_AIN4                (MXC_V_ADC_REVA_CTRL_CH_SEL_AIN4 << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_AIN4 Setting */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_AIN5                ((uint32_t)0x5UL) /**< CTRL_CH_SEL_AIN5 Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_AIN5                (MXC_V_ADC_REVA_CTRL_CH_SEL_AIN5 << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_AIN5 Setting */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_AIN6                ((uint32_t)0x6UL) /**< CTRL_CH_SEL_AIN6 Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_AIN6                (MXC_V_ADC_REVA_CTRL_CH_SEL_AIN6 << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_AIN6 Setting */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_AIN7                ((uint32_t)0x7UL) /**< CTRL_CH_SEL_AIN7 Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_AIN7                (MXC_V_ADC_REVA_CTRL_CH_SEL_AIN7 << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_AIN7 Setting */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_VCOREA              ((uint32_t)0x8UL) /**< CTRL_CH_SEL_VCOREA Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_VCOREA              (MXC_V_ADC_REVA_CTRL_CH_SEL_VCOREA << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_VCOREA Setting */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_VCOREB              ((uint32_t)0x9UL) /**< CTRL_CH_SEL_VCOREB Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_VCOREB              (MXC_V_ADC_REVA_CTRL_CH_SEL_VCOREB << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_VCOREB Setting */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_VRXOUT              ((uint32_t)0xAUL) /**< CTRL_CH_SEL_VRXOUT Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_VRXOUT              (MXC_V_ADC_REVA_CTRL_CH_SEL_VRXOUT << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_VRXOUT Setting */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_VTXOUT              ((uint32_t)0xBUL) /**< CTRL_CH_SEL_VTXOUT Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_VTXOUT              (MXC_V_ADC_REVA_CTRL_CH_SEL_VTXOUT << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_VTXOUT Setting */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_VDDA                ((uint32_t)0xCUL) /**< CTRL_CH_SEL_VDDA Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_VDDA                (MXC_V_ADC_REVA_CTRL_CH_SEL_VDDA << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_VDDA Setting */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_VDDB                ((uint32_t)0xDUL) /**< CTRL_CH_SEL_VDDB Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_VDDB                (MXC_V_ADC_REVA_CTRL_CH_SEL_VDDB << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_VDDB Setting */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_VDDIO               ((uint32_t)0xEUL) /**< CTRL_CH_SEL_VDDIO Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_VDDIO               (MXC_V_ADC_REVA_CTRL_CH_SEL_VDDIO << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_VDDIO Setting */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_VDDIOH              ((uint32_t)0xFUL) /**< CTRL_CH_SEL_VDDIOH Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_VDDIOH              (MXC_V_ADC_REVA_CTRL_CH_SEL_VDDIOH << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_VDDIOH Setting */
 #define MXC_V_ADC_REVA_CTRL_CH_SEL_VREGI               ((uint32_t)0x10UL) /**< CTRL_CH_SEL_VREGI Value */
 #define MXC_S_ADC_REVA_CTRL_CH_SEL_VREGI               (MXC_V_ADC_REVA_CTRL_CH_SEL_VREGI << MXC_F_ADC_REVA_CTRL_CH_SEL_POS) /**< CTRL_CH_SEL_VREGI Setting */

 #define MXC_F_ADC_REVA_CTRL_ADC_DIVSEL_POS             17 /**< CTRL_ADC_DIVSEL Position */
 #define MXC_F_ADC_REVA_CTRL_ADC_DIVSEL                 ((uint32_t)(0x3UL << MXC_F_ADC_REVA_CTRL_ADC_DIVSEL_POS)) /**< CTRL_ADC_DIVSEL Mask */
 #define MXC_V_ADC_REVA_CTRL_ADC_DIVSEL_DIV1            ((uint32_t)0x0UL) /**< CTRL_ADC_DIVSEL_DIV1 Value */
 #define MXC_S_ADC_REVA_CTRL_ADC_DIVSEL_DIV1            (MXC_V_ADC_REVA_CTRL_ADC_DIVSEL_DIV1 << MXC_F_ADC_REVA_CTRL_ADC_DIVSEL_POS) /**< CTRL_ADC_DIVSEL_DIV1 Setting */
 #define MXC_V_ADC_REVA_CTRL_ADC_DIVSEL_DIV2            ((uint32_t)0x1UL) /**< CTRL_ADC_DIVSEL_DIV2 Value */
 #define MXC_S_ADC_REVA_CTRL_ADC_DIVSEL_DIV2            (MXC_V_ADC_REVA_CTRL_ADC_DIVSEL_DIV2 << MXC_F_ADC_REVA_CTRL_ADC_DIVSEL_POS) /**< CTRL_ADC_DIVSEL_DIV2 Setting */
 #define MXC_V_ADC_REVA_CTRL_ADC_DIVSEL_DIV3            ((uint32_t)0x2UL) /**< CTRL_ADC_DIVSEL_DIV3 Value */
 #define MXC_S_ADC_REVA_CTRL_ADC_DIVSEL_DIV3            (MXC_V_ADC_REVA_CTRL_ADC_DIVSEL_DIV3 << MXC_F_ADC_REVA_CTRL_ADC_DIVSEL_POS) /**< CTRL_ADC_DIVSEL_DIV3 Setting */
 #define MXC_V_ADC_REVA_CTRL_ADC_DIVSEL_DIV4            ((uint32_t)0x3UL) /**< CTRL_ADC_DIVSEL_DIV4 Value */
 #define MXC_S_ADC_REVA_CTRL_ADC_DIVSEL_DIV4            (MXC_V_ADC_REVA_CTRL_ADC_DIVSEL_DIV4 << MXC_F_ADC_REVA_CTRL_ADC_DIVSEL_POS) /**< CTRL_ADC_DIVSEL_DIV4 Setting */

 #define MXC_F_ADC_REVA_CTRL_DATA_ALIGN_POS             20 /**< CTRL_DATA_ALIGN Position */
 #define MXC_F_ADC_REVA_CTRL_DATA_ALIGN                 ((uint32_t)(0x1UL << MXC_F_ADC_REVA_CTRL_DATA_ALIGN_POS)) /**< CTRL_DATA_ALIGN Mask */

/**@} end of group ADC_REVA_CTRL_Register */

/**
 * @ingroup  adc_reva_registers
 * @defgroup ADC_REVA_STATUS ADC_REVA_STATUS
 * @brief    ADC Status
 * @{
 */
 #define MXC_F_ADC_REVA_STATUS_ACTIVE_POS               0 /**< STATUS_ACTIVE Position */
 #define MXC_F_ADC_REVA_STATUS_ACTIVE                   ((uint32_t)(0x1UL << MXC_F_ADC_REVA_STATUS_ACTIVE_POS)) /**< STATUS_ACTIVE Mask */

 #define MXC_F_ADC_REVA_STATUS_AFE_PWR_UP_ACTIVE_POS    2 /**< STATUS_AFE_PWR_UP_ACTIVE Position */
 #define MXC_F_ADC_REVA_STATUS_AFE_PWR_UP_ACTIVE        ((uint32_t)(0x1UL << MXC_F_ADC_REVA_STATUS_AFE_PWR_UP_ACTIVE_POS)) /**< STATUS_AFE_PWR_UP_ACTIVE Mask */

 #define MXC_F_ADC_REVA_STATUS_OVERFLOW_POS             3 /**< STATUS_OVERFLOW Position */
 #define MXC_F_ADC_REVA_STATUS_OVERFLOW                 ((uint32_t)(0x1UL << MXC_F_ADC_REVA_STATUS_OVERFLOW_POS)) /**< STATUS_OVERFLOW Mask */

/**@} end of group ADC_REVA_STATUS_Register */

/**
 * @ingroup  adc_reva_registers
 * @defgroup ADC_REVA_DATA ADC_REVA_DATA
 * @brief    ADC Output Data
 * @{
 */
 #define MXC_F_ADC_REVA_DATA_ADC_DATA_POS               0 /**< DATA_ADC_DATA Position */
 #define MXC_F_ADC_REVA_DATA_ADC_DATA                   ((uint32_t)(0xFFFFUL << MXC_F_ADC_REVA_DATA_ADC_DATA_POS)) /**< DATA_ADC_DATA Mask */

/**@} end of group ADC_REVA_DATA_Register */

/**
 * @ingroup  adc_reva_registers
 * @defgroup ADC_REVA_INTR ADC_REVA_INTR
 * @brief    ADC Interrupt Control Register
 * @{
 */
 #define MXC_F_ADC_REVA_INTR_DONE_IE_POS                0 /**< INTR_DONE_IE Position */
 #define MXC_F_ADC_REVA_INTR_DONE_IE                    ((uint32_t)(0x1UL << MXC_F_ADC_REVA_INTR_DONE_IE_POS)) /**< INTR_DONE_IE Mask */

 #define MXC_F_ADC_REVA_INTR_REF_READY_IE_POS           1 /**< INTR_REF_READY_IE Position */
 #define MXC_F_ADC_REVA_INTR_REF_READY_IE               ((uint32_t)(0x1UL << MXC_F_ADC_REVA_INTR_REF_READY_IE_POS)) /**< INTR_REF_READY_IE Mask */

 #define MXC_F_ADC_REVA_INTR_HI_LIMIT_IE_POS            2 /**< INTR_HI_LIMIT_IE Position */
 #define MXC_F_ADC_REVA_INTR_HI_LIMIT_IE                ((uint32_t)(0x1UL << MXC_F_ADC_REVA_INTR_HI_LIMIT_IE_POS)) /**< INTR_HI_LIMIT_IE Mask */

 #define MXC_F_ADC_REVA_INTR_LO_LIMIT_IE_POS            3 /**< INTR_LO_LIMIT_IE Position */
 #define MXC_F_ADC_REVA_INTR_LO_LIMIT_IE                ((uint32_t)(0x1UL << MXC_F_ADC_REVA_INTR_LO_LIMIT_IE_POS)) /**< INTR_LO_LIMIT_IE Mask */

 #define MXC_F_ADC_REVA_INTR_OVERFLOW_IE_POS            4 /**< INTR_OVERFLOW_IE Position */
 #define MXC_F_ADC_REVA_INTR_OVERFLOW_IE                ((uint32_t)(0x1UL << MXC_F_ADC_REVA_INTR_OVERFLOW_IE_POS)) /**< INTR_OVERFLOW_IE Mask */

 #define MXC_F_ADC_REVA_INTR_DONE_IF_POS                16 /**< INTR_DONE_IF Position */
 #define MXC_F_ADC_REVA_INTR_DONE_IF                    ((uint32_t)(0x1UL << MXC_F_ADC_REVA_INTR_DONE_IF_POS)) /**< INTR_DONE_IF Mask */

 #define MXC_F_ADC_REVA_INTR_REF_READY_IF_POS           17 /**< INTR_REF_READY_IF Position */
 #define MXC_F_ADC_REVA_INTR_REF_READY_IF               ((uint32_t)(0x1UL << MXC_F_ADC_REVA_INTR_REF_READY_IF_POS)) /**< INTR_REF_READY_IF Mask */

 #define MXC_F_ADC_REVA_INTR_HI_LIMIT_IF_POS            18 /**< INTR_HI_LIMIT_IF Position */
 #define MXC_F_ADC_REVA_INTR_HI_LIMIT_IF                ((uint32_t)(0x1UL << MXC_F_ADC_REVA_INTR_HI_LIMIT_IF_POS)) /**< INTR_HI_LIMIT_IF Mask */

 #define MXC_F_ADC_REVA_INTR_LO_LIMIT_IF_POS            19 /**< INTR_LO_LIMIT_IF Position */
 #define MXC_F_ADC_REVA_INTR_LO_LIMIT_IF                ((uint32_t)(0x1UL << MXC_F_ADC_REVA_INTR_LO_LIMIT_IF_POS)) /**< INTR_LO_LIMIT_IF Mask */

 #define MXC_F_ADC_REVA_INTR_OVERFLOW_IF_POS            20 /**< INTR_OVERFLOW_IF Position */
 #define MXC_F_ADC_REVA_INTR_OVERFLOW_IF                ((uint32_t)(0x1UL << MXC_F_ADC_REVA_INTR_OVERFLOW_IF_POS)) /**< INTR_OVERFLOW_IF Mask */

 #define MXC_F_ADC_REVA_INTR_PENDING_POS                22 /**< INTR_PENDING Position */
 #define MXC_F_ADC_REVA_INTR_PENDING                    ((uint32_t)(0x1UL << MXC_F_ADC_REVA_INTR_PENDING_POS)) /**< INTR_PENDING Mask */

/**@} end of group ADC_REVA_INTR_Register */

/**
 * @ingroup  adc_reva_registers
 * @defgroup ADC_REVA_LIMIT ADC_REVA_LIMIT
 * @brief    ADC Limit
 * @{
 */
 #define MXC_F_ADC_REVA_LIMIT_CH_LO_LIMIT_POS           0 /**< LIMIT_CH_LO_LIMIT Position */
 #define MXC_F_ADC_REVA_LIMIT_CH_LO_LIMIT               ((uint32_t)(0x3FFUL << MXC_F_ADC_REVA_LIMIT_CH_LO_LIMIT_POS)) /**< LIMIT_CH_LO_LIMIT Mask */

 #define MXC_F_ADC_REVA_LIMIT_CH_HI_LIMIT_POS           12 /**< LIMIT_CH_HI_LIMIT Position */
 #define MXC_F_ADC_REVA_LIMIT_CH_HI_LIMIT               ((uint32_t)(0x3FFUL << MXC_F_ADC_REVA_LIMIT_CH_HI_LIMIT_POS)) /**< LIMIT_CH_HI_LIMIT Mask */

 #define MXC_F_ADC_REVA_LIMIT_CH_SEL_POS                24 /**< LIMIT_CH_SEL Position */
 #define MXC_F_ADC_REVA_LIMIT_CH_SEL                    ((uint32_t)(0x1FUL << MXC_F_ADC_REVA_LIMIT_CH_SEL_POS)) /**< LIMIT_CH_SEL Mask */

 #define MXC_F_ADC_REVA_LIMIT_CH_LO_LIMIT_EN_POS        29 /**< LIMIT_CH_LO_LIMIT_EN Position */
 #define MXC_F_ADC_REVA_LIMIT_CH_LO_LIMIT_EN            ((uint32_t)(0x1UL << MXC_F_ADC_REVA_LIMIT_CH_LO_LIMIT_EN_POS)) /**< LIMIT_CH_LO_LIMIT_EN Mask */

 #define MXC_F_ADC_REVA_LIMIT_CH_HI_LIMIT_EN_POS        30 /**< LIMIT_CH_HI_LIMIT_EN Position */
 #define MXC_F_ADC_REVA_LIMIT_CH_HI_LIMIT_EN            ((uint32_t)(0x1UL << MXC_F_ADC_REVA_LIMIT_CH_HI_LIMIT_EN_POS)) /**< LIMIT_CH_HI_LIMIT_EN Mask */

/**@} end of group ADC_REVA_LIMIT_Register */

#ifdef __cplusplus
}
#endif

#endif /* _ADC_REVA_REGS_H_ */
