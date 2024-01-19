/**
 * @file    sdma_regs.h
 * @brief   Registers, Bit Masks and Bit Positions for the SDMA Peripheral Module.
 */

/* ****************************************************************************
 * Copyright (C) 2016 Maxim Integrated Products, Inc., All Rights Reserved.
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
 *
 *************************************************************************** */

#ifndef _SDMA_REGS_H_
#define _SDMA_REGS_H_

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
 * @ingroup     sdma
 * @defgroup    sdma_registers SDMA_Registers
 * @brief       Registers, Bit Masks and Bit Positions for the SDMA Peripheral Module.
 * @details Smart DMA
 */

/**
 * @ingroup sdma_registers
 * Structure type to access the SDMA Registers.
 */
typedef struct {
    __I  uint32_t ip;                   /**< <tt>\b 0x00:</tt> SDMA IP Register */
    __I  uint32_t sp;                   /**< <tt>\b 0x04:</tt> SDMA SP Register */
    __I  uint32_t dp0;                  /**< <tt>\b 0x08:</tt> SDMA DP0 Register */
    __I  uint32_t dp1;                  /**< <tt>\b 0x0C:</tt> SDMA DP1 Register */
    __I  uint32_t bp;                   /**< <tt>\b 0x10:</tt> SDMA BP Register */
    __I  uint32_t offs;                 /**< <tt>\b 0x14:</tt> SDMA OFFS Register */
    __I  uint32_t lc0;                  /**< <tt>\b 0x18:</tt> SDMA LC0 Register */
    __I  uint32_t lc1;                  /**< <tt>\b 0x1C:</tt> SDMA LC1 Register */
    __I  uint32_t a0;                   /**< <tt>\b 0x20:</tt> SDMA A0 Register */
    __I  uint32_t a1;                   /**< <tt>\b 0x24:</tt> SDMA A1 Register */
    __I  uint32_t a2;                   /**< <tt>\b 0x28:</tt> SDMA A2 Register */
    __I  uint32_t a3;                   /**< <tt>\b 0x2C:</tt> SDMA A3 Register */
    __I  uint32_t wdcn;                 /**< <tt>\b 0x30:</tt> SDMA WDCN Register */
    __R  uint32_t rsv_0x34_0x7f[19];
    __IO uint32_t int_mux_ctrl0;        /**< <tt>\b 0x80:</tt> SDMA INT_MUX_CTRL0 Register */
    __IO uint32_t int_mux_ctrl1;        /**< <tt>\b 0x84:</tt> SDMA INT_MUX_CTRL1 Register */
    __IO uint32_t int_mux_ctrl2;        /**< <tt>\b 0x88:</tt> SDMA INT_MUX_CTRL2 Register */
    __IO uint32_t int_mux_ctrl3;        /**< <tt>\b 0x8C:</tt> SDMA INT_MUX_CTRL3 Register */
    __IO uint32_t ip_addr;              /**< <tt>\b 0x90:</tt> SDMA IP_ADDR Register */
    __IO uint32_t ctrl;                 /**< <tt>\b 0x94:</tt> SDMA CTRL Register */
    __R  uint32_t rsv_0x98_0x9f[2];
    __IO uint32_t int_in_ctrl;          /**< <tt>\b 0xA0:</tt> SDMA INT_IN_CTRL Register */
    __IO uint32_t int_in_flag;          /**< <tt>\b 0xA4:</tt> SDMA INT_IN_FLAG Register */
    __IO uint32_t int_in_ie;            /**< <tt>\b 0xA8:</tt> SDMA INT_IN_IE Register */
    __R  uint32_t rsv_0xac;
    __IO uint32_t irq_flag;             /**< <tt>\b 0xB0:</tt> SDMA IRQ_FLAG Register */
    __IO uint32_t irq_ie;               /**< <tt>\b 0xB4:</tt> SDMA IRQ_IE Register */
} mxc_sdma_regs_t;

/* Register offsets for module SDMA */
/**
 * @ingroup    sdma_registers
 * @defgroup   SDMA_Register_Offsets Register Offsets
 * @brief      SDMA Peripheral Register Offsets from the SDMA Base Peripheral Address.
 * @{
 */
 #define MXC_R_SDMA_IP                      ((uint32_t)0x00000000UL) /**< Offset from SDMA Base Address: <tt> 0x0000</tt> */
 #define MXC_R_SDMA_SP                      ((uint32_t)0x00000004UL) /**< Offset from SDMA Base Address: <tt> 0x0004</tt> */
 #define MXC_R_SDMA_DP0                     ((uint32_t)0x00000008UL) /**< Offset from SDMA Base Address: <tt> 0x0008</tt> */
 #define MXC_R_SDMA_DP1                     ((uint32_t)0x0000000CUL) /**< Offset from SDMA Base Address: <tt> 0x000C</tt> */
 #define MXC_R_SDMA_BP                      ((uint32_t)0x00000010UL) /**< Offset from SDMA Base Address: <tt> 0x0010</tt> */
 #define MXC_R_SDMA_OFFS                    ((uint32_t)0x00000014UL) /**< Offset from SDMA Base Address: <tt> 0x0014</tt> */
 #define MXC_R_SDMA_LC0                     ((uint32_t)0x00000018UL) /**< Offset from SDMA Base Address: <tt> 0x0018</tt> */
 #define MXC_R_SDMA_LC1                     ((uint32_t)0x0000001CUL) /**< Offset from SDMA Base Address: <tt> 0x001C</tt> */
 #define MXC_R_SDMA_A0                      ((uint32_t)0x00000020UL) /**< Offset from SDMA Base Address: <tt> 0x0020</tt> */
 #define MXC_R_SDMA_A1                      ((uint32_t)0x00000024UL) /**< Offset from SDMA Base Address: <tt> 0x0024</tt> */
 #define MXC_R_SDMA_A2                      ((uint32_t)0x00000028UL) /**< Offset from SDMA Base Address: <tt> 0x0028</tt> */
 #define MXC_R_SDMA_A3                      ((uint32_t)0x0000002CUL) /**< Offset from SDMA Base Address: <tt> 0x002C</tt> */
 #define MXC_R_SDMA_WDCN                    ((uint32_t)0x00000030UL) /**< Offset from SDMA Base Address: <tt> 0x0030</tt> */
 #define MXC_R_SDMA_INT_MUX_CTRL0           ((uint32_t)0x00000080UL) /**< Offset from SDMA Base Address: <tt> 0x0080</tt> */
 #define MXC_R_SDMA_INT_MUX_CTRL1           ((uint32_t)0x00000084UL) /**< Offset from SDMA Base Address: <tt> 0x0084</tt> */
 #define MXC_R_SDMA_INT_MUX_CTRL2           ((uint32_t)0x00000088UL) /**< Offset from SDMA Base Address: <tt> 0x0088</tt> */
 #define MXC_R_SDMA_INT_MUX_CTRL3           ((uint32_t)0x0000008CUL) /**< Offset from SDMA Base Address: <tt> 0x008C</tt> */
 #define MXC_R_SDMA_IP_ADDR                 ((uint32_t)0x00000090UL) /**< Offset from SDMA Base Address: <tt> 0x0090</tt> */
 #define MXC_R_SDMA_CTRL                    ((uint32_t)0x00000094UL) /**< Offset from SDMA Base Address: <tt> 0x0094</tt> */
 #define MXC_R_SDMA_INT_IN_CTRL             ((uint32_t)0x000000A0UL) /**< Offset from SDMA Base Address: <tt> 0x00A0</tt> */
 #define MXC_R_SDMA_INT_IN_FLAG             ((uint32_t)0x000000A4UL) /**< Offset from SDMA Base Address: <tt> 0x00A4</tt> */
 #define MXC_R_SDMA_INT_IN_IE               ((uint32_t)0x000000A8UL) /**< Offset from SDMA Base Address: <tt> 0x00A8</tt> */
 #define MXC_R_SDMA_IRQ_FLAG                ((uint32_t)0x000000B0UL) /**< Offset from SDMA Base Address: <tt> 0x00B0</tt> */
 #define MXC_R_SDMA_IRQ_IE                  ((uint32_t)0x000000B4UL) /**< Offset from SDMA Base Address: <tt> 0x00B4</tt> */
/**@} end of group sdma_registers */

/**
 * @ingroup  sdma_registers
 * @defgroup SDMA_INT_MUX_CTRL0 SDMA_INT_MUX_CTRL0
 * @brief    Interrupt Mux Control 0.
 * @{
 */
 #define MXC_F_SDMA_INT_MUX_CTRL0_INTSEL16_POS          0 /**< INT_MUX_CTRL0_INTSEL16 Position */
 #define MXC_F_SDMA_INT_MUX_CTRL0_INTSEL16              ((uint32_t)(0xFFUL << MXC_F_SDMA_INT_MUX_CTRL0_INTSEL16_POS)) /**< INT_MUX_CTRL0_INTSEL16 Mask */

 #define MXC_F_SDMA_INT_MUX_CTRL0_INTSEL17_POS          8 /**< INT_MUX_CTRL0_INTSEL17 Position */
 #define MXC_F_SDMA_INT_MUX_CTRL0_INTSEL17              ((uint32_t)(0xFFUL << MXC_F_SDMA_INT_MUX_CTRL0_INTSEL17_POS)) /**< INT_MUX_CTRL0_INTSEL17 Mask */

 #define MXC_F_SDMA_INT_MUX_CTRL0_INTSEL18_POS          16 /**< INT_MUX_CTRL0_INTSEL18 Position */
 #define MXC_F_SDMA_INT_MUX_CTRL0_INTSEL18              ((uint32_t)(0xFFUL << MXC_F_SDMA_INT_MUX_CTRL0_INTSEL18_POS)) /**< INT_MUX_CTRL0_INTSEL18 Mask */

 #define MXC_F_SDMA_INT_MUX_CTRL0_INTSEL19_POS          24 /**< INT_MUX_CTRL0_INTSEL19 Position */
 #define MXC_F_SDMA_INT_MUX_CTRL0_INTSEL19              ((uint32_t)(0xFFUL << MXC_F_SDMA_INT_MUX_CTRL0_INTSEL19_POS)) /**< INT_MUX_CTRL0_INTSEL19 Mask */

/**@} end of group SDMA_INT_MUX_CTRL0_Register */

/**
 * @ingroup  sdma_registers
 * @defgroup SDMA_INT_MUX_CTRL1 SDMA_INT_MUX_CTRL1
 * @brief    Interrupt Mux Control 1.
 * @{
 */
 #define MXC_F_SDMA_INT_MUX_CTRL1_INTSEL20_POS          0 /**< INT_MUX_CTRL1_INTSEL20 Position */
 #define MXC_F_SDMA_INT_MUX_CTRL1_INTSEL20              ((uint32_t)(0xFFUL << MXC_F_SDMA_INT_MUX_CTRL1_INTSEL20_POS)) /**< INT_MUX_CTRL1_INTSEL20 Mask */

 #define MXC_F_SDMA_INT_MUX_CTRL1_INTSEL21_POS          8 /**< INT_MUX_CTRL1_INTSEL21 Position */
 #define MXC_F_SDMA_INT_MUX_CTRL1_INTSEL21              ((uint32_t)(0xFFUL << MXC_F_SDMA_INT_MUX_CTRL1_INTSEL21_POS)) /**< INT_MUX_CTRL1_INTSEL21 Mask */

 #define MXC_F_SDMA_INT_MUX_CTRL1_INTSEL22_POS          16 /**< INT_MUX_CTRL1_INTSEL22 Position */
 #define MXC_F_SDMA_INT_MUX_CTRL1_INTSEL22              ((uint32_t)(0xFFUL << MXC_F_SDMA_INT_MUX_CTRL1_INTSEL22_POS)) /**< INT_MUX_CTRL1_INTSEL22 Mask */

 #define MXC_F_SDMA_INT_MUX_CTRL1_INTSEL23_POS          24 /**< INT_MUX_CTRL1_INTSEL23 Position */
 #define MXC_F_SDMA_INT_MUX_CTRL1_INTSEL23              ((uint32_t)(0xFFUL << MXC_F_SDMA_INT_MUX_CTRL1_INTSEL23_POS)) /**< INT_MUX_CTRL1_INTSEL23 Mask */

/**@} end of group SDMA_INT_MUX_CTRL1_Register */

/**
 * @ingroup  sdma_registers
 * @defgroup SDMA_INT_MUX_CTRL2 SDMA_INT_MUX_CTRL2
 * @brief    Interrupt Mux Control 2.
 * @{
 */
 #define MXC_F_SDMA_INT_MUX_CTRL2_INTSEL24_POS          0 /**< INT_MUX_CTRL2_INTSEL24 Position */
 #define MXC_F_SDMA_INT_MUX_CTRL2_INTSEL24              ((uint32_t)(0xFFUL << MXC_F_SDMA_INT_MUX_CTRL2_INTSEL24_POS)) /**< INT_MUX_CTRL2_INTSEL24 Mask */

 #define MXC_F_SDMA_INT_MUX_CTRL2_INTSEL25_POS          8 /**< INT_MUX_CTRL2_INTSEL25 Position */
 #define MXC_F_SDMA_INT_MUX_CTRL2_INTSEL25              ((uint32_t)(0xFFUL << MXC_F_SDMA_INT_MUX_CTRL2_INTSEL25_POS)) /**< INT_MUX_CTRL2_INTSEL25 Mask */

 #define MXC_F_SDMA_INT_MUX_CTRL2_INTSEL26_POS          16 /**< INT_MUX_CTRL2_INTSEL26 Position */
 #define MXC_F_SDMA_INT_MUX_CTRL2_INTSEL26              ((uint32_t)(0xFFUL << MXC_F_SDMA_INT_MUX_CTRL2_INTSEL26_POS)) /**< INT_MUX_CTRL2_INTSEL26 Mask */

 #define MXC_F_SDMA_INT_MUX_CTRL2_INTSEL27_POS          24 /**< INT_MUX_CTRL2_INTSEL27 Position */
 #define MXC_F_SDMA_INT_MUX_CTRL2_INTSEL27              ((uint32_t)(0xFFUL << MXC_F_SDMA_INT_MUX_CTRL2_INTSEL27_POS)) /**< INT_MUX_CTRL2_INTSEL27 Mask */

/**@} end of group SDMA_INT_MUX_CTRL2_Register */

/**
 * @ingroup  sdma_registers
 * @defgroup SDMA_INT_MUX_CTRL3 SDMA_INT_MUX_CTRL3
 * @brief    Interrupt Mux Control 3.
 * @{
 */
 #define MXC_F_SDMA_INT_MUX_CTRL3_INTSEL28_POS          0 /**< INT_MUX_CTRL3_INTSEL28 Position */
 #define MXC_F_SDMA_INT_MUX_CTRL3_INTSEL28              ((uint32_t)(0xFFUL << MXC_F_SDMA_INT_MUX_CTRL3_INTSEL28_POS)) /**< INT_MUX_CTRL3_INTSEL28 Mask */

 #define MXC_F_SDMA_INT_MUX_CTRL3_INTSEL29_POS          8 /**< INT_MUX_CTRL3_INTSEL29 Position */
 #define MXC_F_SDMA_INT_MUX_CTRL3_INTSEL29              ((uint32_t)(0xFFUL << MXC_F_SDMA_INT_MUX_CTRL3_INTSEL29_POS)) /**< INT_MUX_CTRL3_INTSEL29 Mask */

 #define MXC_F_SDMA_INT_MUX_CTRL3_INTSEL30_POS          16 /**< INT_MUX_CTRL3_INTSEL30 Position */
 #define MXC_F_SDMA_INT_MUX_CTRL3_INTSEL30              ((uint32_t)(0xFFUL << MXC_F_SDMA_INT_MUX_CTRL3_INTSEL30_POS)) /**< INT_MUX_CTRL3_INTSEL30 Mask */

 #define MXC_F_SDMA_INT_MUX_CTRL3_INTSEL31_POS          24 /**< INT_MUX_CTRL3_INTSEL31 Position */
 #define MXC_F_SDMA_INT_MUX_CTRL3_INTSEL31              ((uint32_t)(0xFFUL << MXC_F_SDMA_INT_MUX_CTRL3_INTSEL31_POS)) /**< INT_MUX_CTRL3_INTSEL31 Mask */

/**@} end of group SDMA_INT_MUX_CTRL3_Register */

/**
 * @ingroup  sdma_registers
 * @defgroup SDMA_IP_ADDR SDMA_IP_ADDR
 * @brief    Configurable starting IP address for Q30E.
 * @{
 */
 #define MXC_F_SDMA_IP_ADDR_START_IP_ADDR_POS           0 /**< IP_ADDR_START_IP_ADDR Position */
 #define MXC_F_SDMA_IP_ADDR_START_IP_ADDR               ((uint32_t)(0xFFFFFFFFUL << MXC_F_SDMA_IP_ADDR_START_IP_ADDR_POS)) /**< IP_ADDR_START_IP_ADDR Mask */

/**@} end of group SDMA_IP_ADDR_Register */

/**
 * @ingroup  sdma_registers
 * @defgroup SDMA_CTRL SDMA_CTRL
 * @brief    Control Register.
 * @{
 */
 #define MXC_F_SDMA_CTRL_EN_POS                         0 /**< CTRL_EN Position */
 #define MXC_F_SDMA_CTRL_EN                             ((uint32_t)(0x1UL << MXC_F_SDMA_CTRL_EN_POS)) /**< CTRL_EN Mask */

/**@} end of group SDMA_CTRL_Register */

/**
 * @ingroup  sdma_registers
 * @defgroup SDMA_INT_IN_CTRL SDMA_INT_IN_CTRL
 * @brief    Interrupt Input From CPU Control Register.
 * @{
 */
 #define MXC_F_SDMA_INT_IN_CTRL_INTSET_POS              0 /**< INT_IN_CTRL_INTSET Position */
 #define MXC_F_SDMA_INT_IN_CTRL_INTSET                  ((uint32_t)(0x1UL << MXC_F_SDMA_INT_IN_CTRL_INTSET_POS)) /**< INT_IN_CTRL_INTSET Mask */

/**@} end of group SDMA_INT_IN_CTRL_Register */

/**
 * @ingroup  sdma_registers
 * @defgroup SDMA_INT_IN_FLAG SDMA_INT_IN_FLAG
 * @brief    Interrupt Input From CPU Flag.
 * @{
 */
 #define MXC_F_SDMA_INT_IN_FLAG_INTFLAG_POS             0 /**< INT_IN_FLAG_INTFLAG Position */
 #define MXC_F_SDMA_INT_IN_FLAG_INTFLAG                 ((uint32_t)(0x1UL << MXC_F_SDMA_INT_IN_FLAG_INTFLAG_POS)) /**< INT_IN_FLAG_INTFLAG Mask */

/**@} end of group SDMA_INT_IN_FLAG_Register */

/**
 * @ingroup  sdma_registers
 * @defgroup SDMA_INT_IN_IE SDMA_INT_IN_IE
 * @brief    Interrupt Input From CPU Enable.
 * @{
 */
 #define MXC_F_SDMA_INT_IN_IE_INT_IN_EN_POS             0 /**< INT_IN_IE_INT_IN_EN Position */
 #define MXC_F_SDMA_INT_IN_IE_INT_IN_EN                 ((uint32_t)(0x1UL << MXC_F_SDMA_INT_IN_IE_INT_IN_EN_POS)) /**< INT_IN_IE_INT_IN_EN Mask */

/**@} end of group SDMA_INT_IN_IE_Register */

/**
 * @ingroup  sdma_registers
 * @defgroup SDMA_IRQ_FLAG SDMA_IRQ_FLAG
 * @brief    Interrupt Output To CPU Flag.
 * @{
 */
 #define MXC_F_SDMA_IRQ_FLAG_IRQ_FLAG_POS               0 /**< IRQ_FLAG_IRQ_FLAG Position */
 #define MXC_F_SDMA_IRQ_FLAG_IRQ_FLAG                   ((uint32_t)(0x1UL << MXC_F_SDMA_IRQ_FLAG_IRQ_FLAG_POS)) /**< IRQ_FLAG_IRQ_FLAG Mask */

/**@} end of group SDMA_IRQ_FLAG_Register */

/**
 * @ingroup  sdma_registers
 * @defgroup SDMA_IRQ_IE SDMA_IRQ_IE
 * @brief    Interrupt Output To CPU Control Register.
 * @{
 */
 #define MXC_F_SDMA_IRQ_IE_IRQ_EN_POS                   0 /**< IRQ_IE_IRQ_EN Position */
 #define MXC_F_SDMA_IRQ_IE_IRQ_EN                       ((uint32_t)(0x1UL << MXC_F_SDMA_IRQ_IE_IRQ_EN_POS)) /**< IRQ_IE_IRQ_EN Mask */

/**@} end of group SDMA_IRQ_IE_Register */

#ifdef __cplusplus
}
#endif

#endif /* _SDMA_REGS_H_ */
