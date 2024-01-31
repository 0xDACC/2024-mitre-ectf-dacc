/**
 * @file    cameraif_regs.h
 * @brief   Registers, Bit Masks and Bit Positions for the CAMERAIF Peripheral Module.
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

#ifndef LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32570_INCLUDE_CAMERAIF_REGS_H_
#define LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32570_INCLUDE_CAMERAIF_REGS_H_

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
 * @ingroup     cameraif
 * @defgroup    cameraif_registers CAMERAIF_Registers
 * @brief       Registers, Bit Masks and Bit Positions for the CAMERAIF Peripheral Module.
 * @details     Parallel Camera Interface.
 */

/**
 * @ingroup cameraif_registers
 * Structure type to access the CAMERAIF Registers.
 */
typedef struct {
    __IO uint32_t ver;                  /**< <tt>\b 0x0000:</tt> CAMERAIF VER Register */
    __IO uint32_t fifo_size;            /**< <tt>\b 0x0004:</tt> CAMERAIF FIFO_SIZE Register */
    __IO uint32_t ctrl;                 /**< <tt>\b 0x0008:</tt> CAMERAIF CTRL Register */
    __IO uint32_t int_en;               /**< <tt>\b 0x000C:</tt> CAMERAIF INT_EN Register */
    __IO uint32_t int_fl;               /**< <tt>\b 0x0010:</tt> CAMERAIF INT_FL Register */
    __IO uint32_t ds_timing_codes;      /**< <tt>\b 0x0014:</tt> CAMERAIF DS_TIMING_CODES Register */
    __R  uint32_t rsv_0x18_0x2f[6];
    __IO uint32_t fifo_data;            /**< <tt>\b 0x0030:</tt> CAMERAIF FIFO_DATA Register */
} mxc_cameraif_regs_t;

/* Register offsets for module CAMERAIF */
/**
 * @ingroup    cameraif_registers
 * @defgroup   CAMERAIF_Register_Offsets Register Offsets
 * @brief      CAMERAIF Peripheral Register Offsets from the CAMERAIF Base Peripheral Address.
 * @{
 */
#define MXC_R_CAMERAIF_VER                 ((uint32_t)0x00000000UL) /**< Offset from CAMERAIF Base Address: <tt> 0x0000</tt> */
#define MXC_R_CAMERAIF_FIFO_SIZE           ((uint32_t)0x00000004UL) /**< Offset from CAMERAIF Base Address: <tt> 0x0004</tt> */
#define MXC_R_CAMERAIF_CTRL                ((uint32_t)0x00000008UL) /**< Offset from CAMERAIF Base Address: <tt> 0x0008</tt> */
#define MXC_R_CAMERAIF_INT_EN              ((uint32_t)0x0000000CUL) /**< Offset from CAMERAIF Base Address: <tt> 0x000C</tt> */
#define MXC_R_CAMERAIF_INT_FL              ((uint32_t)0x00000010UL) /**< Offset from CAMERAIF Base Address: <tt> 0x0010</tt> */
#define MXC_R_CAMERAIF_DS_TIMING_CODES     ((uint32_t)0x00000014UL) /**< Offset from CAMERAIF Base Address: <tt> 0x0014</tt> */
#define MXC_R_CAMERAIF_FIFO_DATA           ((uint32_t)0x00000030UL) /**< Offset from CAMERAIF Base Address: <tt> 0x0030</tt> */
/**@} end of group cameraif_registers */

/**
 * @ingroup  cameraif_registers
 * @defgroup CAMERAIF_VER CAMERAIF_VER
 * @brief    Hardware Version.
 * @{
 */
#define MXC_F_CAMERAIF_VER_MINOR_POS                   0 /**< VER_MINOR Position */
#define MXC_F_CAMERAIF_VER_MINOR                       ((uint32_t)(0xFFUL << MXC_F_CAMERAIF_VER_MINOR_POS)) /**< VER_MINOR Mask */

#define MXC_F_CAMERAIF_VER_MAJOR_POS                   8 /**< VER_MAJOR Position */
#define MXC_F_CAMERAIF_VER_MAJOR                       ((uint32_t)(0xFFUL << MXC_F_CAMERAIF_VER_MAJOR_POS)) /**< VER_MAJOR Mask */

/**@} end of group CAMERAIF_VER_Register */

/**
 * @ingroup  cameraif_registers
 * @defgroup CAMERAIF_FIFO_SIZE CAMERAIF_FIFO_SIZE
 * @brief    FIFO Depth.
 * @{
 */
#define MXC_F_CAMERAIF_FIFO_SIZE_FIFO_SIZE_POS         0 /**< FIFO_SIZE_FIFO_SIZE Position */
#define MXC_F_CAMERAIF_FIFO_SIZE_FIFO_SIZE             ((uint32_t)(0xFFUL << MXC_F_CAMERAIF_FIFO_SIZE_FIFO_SIZE_POS)) /**< FIFO_SIZE_FIFO_SIZE Mask */

/**@} end of group CAMERAIF_FIFO_SIZE_Register */

/**
 * @ingroup  cameraif_registers
 * @defgroup CAMERAIF_CTRL CAMERAIF_CTRL
 * @brief    Control Register.
 * @{
 */
#define MXC_F_CAMERAIF_CTRL_READ_MODE_POS              0 /**< CTRL_READ_MODE Position */
#define MXC_F_CAMERAIF_CTRL_READ_MODE                  ((uint32_t)(0x3UL << MXC_F_CAMERAIF_CTRL_READ_MODE_POS)) /**< CTRL_READ_MODE Mask */
#define MXC_V_CAMERAIF_CTRL_READ_MODE_DIS              ((uint32_t)0x0UL) /**< CTRL_READ_MODE_DIS Value */
#define MXC_S_CAMERAIF_CTRL_READ_MODE_DIS              (MXC_V_CAMERAIF_CTRL_READ_MODE_DIS << MXC_F_CAMERAIF_CTRL_READ_MODE_POS) /**< CTRL_READ_MODE_DIS Setting */
#define MXC_V_CAMERAIF_CTRL_READ_MODE_SINGLE_IMG       ((uint32_t)0x1UL) /**< CTRL_READ_MODE_SINGLE_IMG Value */
#define MXC_S_CAMERAIF_CTRL_READ_MODE_SINGLE_IMG       (MXC_V_CAMERAIF_CTRL_READ_MODE_SINGLE_IMG << MXC_F_CAMERAIF_CTRL_READ_MODE_POS) /**< CTRL_READ_MODE_SINGLE_IMG Setting */
#define MXC_V_CAMERAIF_CTRL_READ_MODE_CONTINUOUS       ((uint32_t)0x2UL) /**< CTRL_READ_MODE_CONTINUOUS Value */
#define MXC_S_CAMERAIF_CTRL_READ_MODE_CONTINUOUS       (MXC_V_CAMERAIF_CTRL_READ_MODE_CONTINUOUS << MXC_F_CAMERAIF_CTRL_READ_MODE_POS) /**< CTRL_READ_MODE_CONTINUOUS Setting */

#define MXC_F_CAMERAIF_CTRL_DATA_WIDTH_POS             2 /**< CTRL_DATA_WIDTH Position */
#define MXC_F_CAMERAIF_CTRL_DATA_WIDTH                 ((uint32_t)(0x3UL << MXC_F_CAMERAIF_CTRL_DATA_WIDTH_POS)) /**< CTRL_DATA_WIDTH Mask */
#define MXC_V_CAMERAIF_CTRL_DATA_WIDTH_8BIT            ((uint32_t)0x0UL) /**< CTRL_DATA_WIDTH_8BIT Value */
#define MXC_S_CAMERAIF_CTRL_DATA_WIDTH_8BIT            (MXC_V_CAMERAIF_CTRL_DATA_WIDTH_8BIT << MXC_F_CAMERAIF_CTRL_DATA_WIDTH_POS) /**< CTRL_DATA_WIDTH_8BIT Setting */
#define MXC_V_CAMERAIF_CTRL_DATA_WIDTH_10BIT           ((uint32_t)0x1UL) /**< CTRL_DATA_WIDTH_10BIT Value */
#define MXC_S_CAMERAIF_CTRL_DATA_WIDTH_10BIT           (MXC_V_CAMERAIF_CTRL_DATA_WIDTH_10BIT << MXC_F_CAMERAIF_CTRL_DATA_WIDTH_POS) /**< CTRL_DATA_WIDTH_10BIT Setting */
#define MXC_V_CAMERAIF_CTRL_DATA_WIDTH_12BIT           ((uint32_t)0x2UL) /**< CTRL_DATA_WIDTH_12BIT Value */
#define MXC_S_CAMERAIF_CTRL_DATA_WIDTH_12BIT           (MXC_V_CAMERAIF_CTRL_DATA_WIDTH_12BIT << MXC_F_CAMERAIF_CTRL_DATA_WIDTH_POS) /**< CTRL_DATA_WIDTH_12BIT Setting */

#define MXC_F_CAMERAIF_CTRL_DS_TIMING_EN_POS           4 /**< CTRL_DS_TIMING_EN Position */
#define MXC_F_CAMERAIF_CTRL_DS_TIMING_EN               ((uint32_t)(0x1UL << MXC_F_CAMERAIF_CTRL_DS_TIMING_EN_POS)) /**< CTRL_DS_TIMING_EN Mask */

#define MXC_F_CAMERAIF_CTRL_FIFO_THRSH_POS             5 /**< CTRL_FIFO_THRSH Position */
#define MXC_F_CAMERAIF_CTRL_FIFO_THRSH                 ((uint32_t)(0x1FUL << MXC_F_CAMERAIF_CTRL_FIFO_THRSH_POS)) /**< CTRL_FIFO_THRSH Mask */

#define MXC_F_CAMERAIF_CTRL_RX_DMA_POS                 10 /**< CTRL_RX_DMA Position */
#define MXC_F_CAMERAIF_CTRL_RX_DMA                     ((uint32_t)(0x1UL << MXC_F_CAMERAIF_CTRL_RX_DMA_POS)) /**< CTRL_RX_DMA Mask */

#define MXC_F_CAMERAIF_CTRL_RX_DMA_THRSH_POS           11 /**< CTRL_RX_DMA_THRSH Position */
#define MXC_F_CAMERAIF_CTRL_RX_DMA_THRSH               ((uint32_t)(0xFUL << MXC_F_CAMERAIF_CTRL_RX_DMA_THRSH_POS)) /**< CTRL_RX_DMA_THRSH Mask */

#define MXC_F_CAMERAIF_CTRL_PCIF_SYS_POS               15 /**< CTRL_PCIF_SYS Position */
#define MXC_F_CAMERAIF_CTRL_PCIF_SYS                   ((uint32_t)(0x1UL << MXC_F_CAMERAIF_CTRL_PCIF_SYS_POS)) /**< CTRL_PCIF_SYS Mask */

/**@} end of group CAMERAIF_CTRL_Register */

/**
 * @ingroup  cameraif_registers
 * @defgroup CAMERAIF_INT_EN CAMERAIF_INT_EN
 * @brief    Interupt Enable Register.
 * @{
 */
#define MXC_F_CAMERAIF_INT_EN_IMG_DONE_POS             0 /**< INT_EN_IMG_DONE Position */
#define MXC_F_CAMERAIF_INT_EN_IMG_DONE                 ((uint32_t)(0x1UL << MXC_F_CAMERAIF_INT_EN_IMG_DONE_POS)) /**< INT_EN_IMG_DONE Mask */

#define MXC_F_CAMERAIF_INT_EN_FIFO_FULL_POS            1 /**< INT_EN_FIFO_FULL Position */
#define MXC_F_CAMERAIF_INT_EN_FIFO_FULL                ((uint32_t)(0x1UL << MXC_F_CAMERAIF_INT_EN_FIFO_FULL_POS)) /**< INT_EN_FIFO_FULL Mask */

#define MXC_F_CAMERAIF_INT_EN_FIFO_THRESH_POS          2 /**< INT_EN_FIFO_THRESH Position */
#define MXC_F_CAMERAIF_INT_EN_FIFO_THRESH              ((uint32_t)(0x1UL << MXC_F_CAMERAIF_INT_EN_FIFO_THRESH_POS)) /**< INT_EN_FIFO_THRESH Mask */

#define MXC_F_CAMERAIF_INT_EN_FIFO_NOT_EMPTY_POS       3 /**< INT_EN_FIFO_NOT_EMPTY Position */
#define MXC_F_CAMERAIF_INT_EN_FIFO_NOT_EMPTY           ((uint32_t)(0x1UL << MXC_F_CAMERAIF_INT_EN_FIFO_NOT_EMPTY_POS)) /**< INT_EN_FIFO_NOT_EMPTY Mask */

/**@} end of group CAMERAIF_INT_EN_Register */

/**
 * @ingroup  cameraif_registers
 * @defgroup CAMERAIF_INT_FL CAMERAIF_INT_FL
 * @brief    Interupt Flag Register.
 * @{
 */
#define MXC_F_CAMERAIF_INT_FL_IMG_DONE_POS             0 /**< INT_FL_IMG_DONE Position */
#define MXC_F_CAMERAIF_INT_FL_IMG_DONE                 ((uint32_t)(0x1UL << MXC_F_CAMERAIF_INT_FL_IMG_DONE_POS)) /**< INT_FL_IMG_DONE Mask */

#define MXC_F_CAMERAIF_INT_FL_FIFO_FULL_POS            1 /**< INT_FL_FIFO_FULL Position */
#define MXC_F_CAMERAIF_INT_FL_FIFO_FULL                ((uint32_t)(0x1UL << MXC_F_CAMERAIF_INT_FL_FIFO_FULL_POS)) /**< INT_FL_FIFO_FULL Mask */

#define MXC_F_CAMERAIF_INT_FL_FIFO_THRESH_POS          2 /**< INT_FL_FIFO_THRESH Position */
#define MXC_F_CAMERAIF_INT_FL_FIFO_THRESH              ((uint32_t)(0x1UL << MXC_F_CAMERAIF_INT_FL_FIFO_THRESH_POS)) /**< INT_FL_FIFO_THRESH Mask */

#define MXC_F_CAMERAIF_INT_FL_FIFO_NOT_EMPTY_POS       3 /**< INT_FL_FIFO_NOT_EMPTY Position */
#define MXC_F_CAMERAIF_INT_FL_FIFO_NOT_EMPTY           ((uint32_t)(0x1UL << MXC_F_CAMERAIF_INT_FL_FIFO_NOT_EMPTY_POS)) /**< INT_FL_FIFO_NOT_EMPTY Mask */

/**@} end of group CAMERAIF_INT_FL_Register */

/**
 * @ingroup  cameraif_registers
 * @defgroup CAMERAIF_DS_TIMING_CODES CAMERAIF_DS_TIMING_CODES
 * @brief    DS Timing Code Register.
 * @{
 */
#define MXC_F_CAMERAIF_DS_TIMING_CODES_SAV_POS         0 /**< DS_TIMING_CODES_SAV Position */
#define MXC_F_CAMERAIF_DS_TIMING_CODES_SAV             ((uint32_t)(0xFFUL << MXC_F_CAMERAIF_DS_TIMING_CODES_SAV_POS)) /**< DS_TIMING_CODES_SAV Mask */

#define MXC_F_CAMERAIF_DS_TIMING_CODES_EAV_POS         8 /**< DS_TIMING_CODES_EAV Position */
#define MXC_F_CAMERAIF_DS_TIMING_CODES_EAV             ((uint32_t)(0xFFUL << MXC_F_CAMERAIF_DS_TIMING_CODES_EAV_POS)) /**< DS_TIMING_CODES_EAV Mask */

/**@} end of group CAMERAIF_DS_TIMING_CODES_Register */

/**
 * @ingroup  cameraif_registers
 * @defgroup CAMERAIF_FIFO_DATA CAMERAIF_FIFO_DATA
 * @brief    FIFO DATA Register.
 * @{
 */
#define MXC_F_CAMERAIF_FIFO_DATA_DATA_POS              0 /**< FIFO_DATA_DATA Position */
#define MXC_F_CAMERAIF_FIFO_DATA_DATA                  ((uint32_t)(0xFFFFFFFFUL << MXC_F_CAMERAIF_FIFO_DATA_DATA_POS)) /**< FIFO_DATA_DATA Mask */

/**@} end of group CAMERAIF_FIFO_DATA_Register */

#ifdef __cplusplus
}
#endif

#endif // LIBRARIES_CMSIS_DEVICE_MAXIM_MAX32570_INCLUDE_CAMERAIF_REGS_H_
