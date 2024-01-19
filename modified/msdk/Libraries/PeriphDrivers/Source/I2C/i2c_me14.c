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

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include "mxc_device.h"
#include "mxc_assert.h"
#include "mxc_lock.h"
#include "mxc_sys.h"
#include "mxc_pins.h"
#include "mxc_delay.h"
#include "i2c_regs.h"
#include "dma_regs.h"
#include "i2c.h"
#include "i2c_reva.h"

/* **** Variable Declaration **** */
uint32_t interruptCheck = MXC_F_I2C_INT_FL0_RD_ADDR_MATCH | MXC_F_I2C_INT_FL0_WR_ADDR_MATCH |
                          MXC_F_I2C_INT_FL0_DO_NOT_RESP_ER;

/* **** Function Prototypes **** */

/* ************************************************************************* */
/* Control/Configuration functions                                           */
/* ************************************************************************* */
int MXC_I2C_Init(mxc_i2c_regs_t *i2c, int masterMode, unsigned int slaveAddr)
{
    if (i2c == NULL) {
        return E_NULL_PTR;
    }

    MXC_I2C_Shutdown(i2c); // Clear everything out

    if ((i2c == MXC_I2C0_BUS0) || (i2c == MXC_I2C0_BUS1)) {
        MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_I2C0);
        MXC_GPIO_Config(&gpio_cfg_i2c0);
    } else if ((i2c == MXC_I2C1_BUS0) || (i2c == MXC_I2C1_BUS1)) {
        MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_I2C1);
        MXC_GPIO_Config(&gpio_cfg_i2c1);
    } else if ((i2c == MXC_I2C2_BUS0) || (i2c == MXC_I2C2_BUS1)) {
        MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_I2C2);
        MXC_GPIO_Config(&gpio_cfg_i2c2);
    } else {
        return E_NO_DEVICE;
    }

    return MXC_I2C_RevA_Init((mxc_i2c_reva_regs_t *)i2c, masterMode, slaveAddr);
}

int MXC_I2C_SetSlaveAddr(mxc_i2c_regs_t *i2c, unsigned int slaveAddr, int idx)
{
    return MXC_I2C_RevA_SetSlaveAddr((mxc_i2c_reva_regs_t *)i2c, slaveAddr, idx);
}

int MXC_I2C_Shutdown(mxc_i2c_regs_t *i2c)
{
    // Configure GPIO for I2C
    if ((i2c == MXC_I2C0_BUS0) || (i2c == MXC_I2C0_BUS1)) {
        MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_I2C0);
    } else if ((i2c == MXC_I2C1_BUS0) || (i2c == MXC_I2C1_BUS1)) {
        MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_I2C1);
    } else if ((i2c == MXC_I2C2_BUS0) || (i2c == MXC_I2C2_BUS1)) {
        MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_I2C2);
    } else {
        return E_NO_DEVICE;
    }

    int i2cNum = MXC_I2C_GET_IDX(i2c);

    // Reconcile this with MXC_SYS_I2C_Init when we figure out what to do abotu system level things
    switch (i2cNum) {
    case 0:
        MXC_GCR->rstr0 |= MXC_F_GCR_RSTR0_I2C0;
        break;

    case 1:
        MXC_GCR->rstr1 |= MXC_F_GCR_RSTR1_I2C1;
        break;

    case 2:
        MXC_GCR->rstr1 |= MXC_F_GCR_RSTR1_I2C2;
        break;

    default:
        return E_BAD_PARAM;
    }

    return E_NO_ERROR;
}

int MXC_I2C_SetFrequency(mxc_i2c_regs_t *i2c, unsigned int hz)
{
    return MXC_I2C_RevA_SetFrequency((mxc_i2c_reva_regs_t *)i2c, hz);
}

unsigned int MXC_I2C_GetFrequency(mxc_i2c_regs_t *i2c)
{
    return MXC_I2C_RevA_GetFrequency((mxc_i2c_reva_regs_t *)i2c);
}

int MXC_I2C_ReadyForSleep(mxc_i2c_regs_t *i2c)
{
    return MXC_I2C_RevA_ReadyForSleep((mxc_i2c_reva_regs_t *)i2c);
}

int MXC_I2C_SetClockStretching(mxc_i2c_regs_t *i2c, int enable)
{
    return MXC_I2C_RevA_SetClockStretching((mxc_i2c_reva_regs_t *)i2c, enable);
}

int MXC_I2C_GetClockStretching(mxc_i2c_regs_t *i2c)
{
    return MXC_I2C_RevA_GetClockStretching((mxc_i2c_reva_regs_t *)i2c);
}

/* ************************************************************************* */
/* Low-level functions                                                       */
/* ************************************************************************* */
int MXC_I2C_Start(mxc_i2c_regs_t *i2c)
{
    return MXC_I2C_RevA_Start((mxc_i2c_reva_regs_t *)i2c);
}

int MXC_I2C_Stop(mxc_i2c_regs_t *i2c)
{
    return MXC_I2C_RevA_Stop((mxc_i2c_reva_regs_t *)i2c);
}

int MXC_I2C_WriteByte(mxc_i2c_regs_t *i2c, unsigned char byte)
{
    return MXC_I2C_RevA_WriteByte((mxc_i2c_reva_regs_t *)i2c, byte);
}

int MXC_I2C_ReadByte(mxc_i2c_regs_t *i2c, unsigned char *byte, int ack)
{
    return MXC_I2C_RevA_ReadByte((mxc_i2c_reva_regs_t *)i2c, byte, ack);
}

int MXC_I2C_ReadByteInteractive(mxc_i2c_regs_t *i2c, unsigned char *byte, mxc_i2c_getAck_t getAck)
{
    return MXC_I2C_RevA_ReadByteInteractive((mxc_i2c_reva_regs_t *)i2c, byte,
                                            (mxc_i2c_reva_getAck_t)getAck);
}

int MXC_I2C_Write(mxc_i2c_regs_t *i2c, unsigned char *bytes, unsigned int *len)
{
    return MXC_I2C_RevA_Write((mxc_i2c_reva_regs_t *)i2c, bytes, len);
}

int MXC_I2C_Read(mxc_i2c_regs_t *i2c, unsigned char *bytes, unsigned int *len, int ack)
{
    return MXC_I2C_RevA_Read((mxc_i2c_reva_regs_t *)i2c, bytes, len, ack);
}

int MXC_I2C_ReadRXFIFO(mxc_i2c_regs_t *i2c, volatile unsigned char *bytes, unsigned int len)
{
    return MXC_I2C_RevA_ReadRXFIFO((mxc_i2c_reva_regs_t *)i2c, bytes, len);
}

int MXC_I2C_ReadRXFIFODMA(mxc_i2c_regs_t *i2c, unsigned char *bytes, unsigned int len,
                          mxc_i2c_dma_complete_cb_t callback, mxc_dma_regs_t *dma)
{
    uint8_t i2cNum;
    mxc_dma_config_t config;

    if (MXC_DMA_GET_IDX(dma) == -1) {
        return E_BAD_PARAM;
    }

    i2cNum = MXC_I2C_GET_IDX(i2c);
    switch (i2cNum) {
    case 0:
        config.reqsel = MXC_DMA_REQUEST_I2C0RX;
        break;

    case 1:
        config.reqsel = MXC_DMA_REQUEST_I2C1RX;
        break;

    case 2:
        config.reqsel = MXC_DMA_REQUEST_I2C2RX;
        break;
    }
    return MXC_I2C_RevA_ReadRXFIFODMA((mxc_i2c_reva_regs_t *)i2c, bytes, len,
                                      (mxc_i2c_reva_dma_complete_cb_t)callback, config, dma);
}

int MXC_I2C_GetRXFIFOAvailable(mxc_i2c_regs_t *i2c)
{
    return MXC_I2C_RevA_GetRXFIFOAvailable((mxc_i2c_reva_regs_t *)i2c);
}

int MXC_I2C_WriteTXFIFO(mxc_i2c_regs_t *i2c, volatile unsigned char *bytes, unsigned int len)
{
    return MXC_I2C_RevA_WriteTXFIFO((mxc_i2c_reva_regs_t *)i2c, bytes, len);
}

int MXC_I2C_WriteTXFIFODMA(mxc_i2c_regs_t *i2c, unsigned char *bytes, unsigned int len,
                           mxc_i2c_dma_complete_cb_t callback, mxc_dma_regs_t *dma)
{
    uint8_t i2cNum;
    mxc_dma_config_t config;

    if (MXC_DMA_GET_IDX(dma) == -1) {
        return E_BAD_PARAM;
    }

    i2cNum = MXC_I2C_GET_IDX(i2c);
    switch (i2cNum) {
    case 0:
        config.reqsel = MXC_DMA_REQUEST_I2C0TX;
        break;

    case 1:
        config.reqsel = MXC_DMA_REQUEST_I2C1TX;
        break;
    }
    return MXC_I2C_RevA_WriteTXFIFODMA((mxc_i2c_reva_regs_t *)i2c, bytes, len,
                                       (mxc_i2c_reva_dma_complete_cb_t)callback, config, dma);
}

int MXC_I2C_GetTXFIFOAvailable(mxc_i2c_regs_t *i2c)
{
    return MXC_I2C_RevA_GetTXFIFOAvailable((mxc_i2c_reva_regs_t *)i2c);
}

void MXC_I2C_ClearRXFIFO(mxc_i2c_regs_t *i2c)
{
    MXC_I2C_RevA_ClearRXFIFO((mxc_i2c_reva_regs_t *)i2c);
}

void MXC_I2C_ClearTXFIFO(mxc_i2c_regs_t *i2c)
{
    MXC_I2C_RevA_ClearTXFIFO((mxc_i2c_reva_regs_t *)i2c);
}

int MXC_I2C_GetFlags(mxc_i2c_regs_t *i2c, unsigned int *flags0, unsigned int *flags1)
{
    return MXC_I2C_RevA_GetFlags((mxc_i2c_reva_regs_t *)i2c, flags0, flags1);
}

void MXC_I2C_ClearFlags(mxc_i2c_regs_t *i2c, unsigned int flags0, unsigned int flags1)
{
    MXC_I2C_RevA_ClearFlags((mxc_i2c_reva_regs_t *)i2c, flags0, flags1);
}

void MXC_I2C_EnableInt(mxc_i2c_regs_t *i2c, unsigned int flags0, unsigned int flags1)
{
    MXC_I2C_RevA_EnableInt((mxc_i2c_reva_regs_t *)i2c, flags0, flags1);
}

void MXC_I2C_DisableInt(mxc_i2c_regs_t *i2c, unsigned int flags0, unsigned int flags1)
{
    MXC_I2C_RevA_DisableInt((mxc_i2c_reva_regs_t *)i2c, flags0, flags1);
}

void MXC_I2C_EnablePreload(mxc_i2c_regs_t *i2c)
{
    MXC_I2C_RevA_EnablePreload((mxc_i2c_reva_regs_t *)i2c);
}

void MXC_I2C_DisablePreload(mxc_i2c_regs_t *i2c)
{
    MXC_I2C_RevA_DisablePreload((mxc_i2c_reva_regs_t *)i2c);
}

void MXC_I2C_EnableGeneralCall(mxc_i2c_regs_t *i2c)
{
    MXC_I2C_RevA_EnableGeneralCall((mxc_i2c_reva_regs_t *)i2c);
}

void MXC_I2C_DisableGeneralCall(mxc_i2c_regs_t *i2c)
{
    MXC_I2C_RevA_DisableGeneralCall((mxc_i2c_reva_regs_t *)i2c);
}

void MXC_I2C_SetTimeout(mxc_i2c_regs_t *i2c, unsigned int timeout)
{
    MXC_I2C_RevA_SetTimeout((mxc_i2c_reva_regs_t *)i2c, timeout);
}

unsigned int MXC_I2C_GetTimeout(mxc_i2c_regs_t *i2c)
{
    return MXC_I2C_RevA_GetTimeout((mxc_i2c_reva_regs_t *)i2c);
}

int MXC_I2C_Recover(mxc_i2c_regs_t *i2c, unsigned int retries)
{
    return MXC_I2C_RevA_Recover((mxc_i2c_reva_regs_t *)i2c, retries);
}

/* ************************************************************************* */
/* Transaction level functions                                               */
/* ************************************************************************* */

int MXC_I2C_MasterTransaction(mxc_i2c_req_t *req)
{
    return MXC_I2C_RevA_MasterTransaction((mxc_i2c_reva_req_t *)req);
}

int MXC_I2C_MasterTransactionAsync(mxc_i2c_req_t *req)
{
    return MXC_I2C_RevA_MasterTransactionAsync((mxc_i2c_reva_req_t *)req);
}

int MXC_I2C_MasterTransactionDMA(mxc_i2c_req_t *req, mxc_dma_regs_t *dma)
{
    if (MXC_DMA_GET_IDX(dma) == -1) {
        return E_BAD_PARAM;
    }

    return MXC_I2C_RevA_MasterTransactionDMA((mxc_i2c_reva_req_t *)req, dma);
}

int MXC_I2C_SlaveTransaction(mxc_i2c_regs_t *i2c, mxc_i2c_slave_handler_t callback)
{
    return MXC_I2C_RevA_SlaveTransaction((mxc_i2c_reva_regs_t *)i2c,
                                         (mxc_i2c_reva_slave_handler_t)callback, interruptCheck);
}

int MXC_I2C_SlaveTransactionAsync(mxc_i2c_regs_t *i2c, mxc_i2c_slave_handler_t callback)
{
    return MXC_I2C_RevA_SlaveTransactionAsync(
        (mxc_i2c_reva_regs_t *)i2c, (mxc_i2c_reva_slave_handler_t)callback, interruptCheck);
}

int MXC_I2C_SetRXThreshold(mxc_i2c_regs_t *i2c, unsigned int numBytes)
{
    return MXC_I2C_RevA_SetRXThreshold((mxc_i2c_reva_regs_t *)i2c, numBytes);
}

unsigned int MXC_I2C_GetRXThreshold(mxc_i2c_regs_t *i2c)
{
    return MXC_I2C_RevA_GetRXThreshold((mxc_i2c_reva_regs_t *)i2c);
}

int MXC_I2C_SetTXThreshold(mxc_i2c_regs_t *i2c, unsigned int numBytes)
{
    return MXC_I2C_RevA_SetTXThreshold((mxc_i2c_reva_regs_t *)i2c, numBytes);
}

unsigned int MXC_I2C_GetTXThreshold(mxc_i2c_regs_t *i2c)
{
    return MXC_I2C_RevA_GetTXThreshold((mxc_i2c_reva_regs_t *)i2c);
}

void MXC_I2C_AsyncStop(mxc_i2c_regs_t *i2c)
{
    MXC_I2C_RevA_AsyncStop((mxc_i2c_reva_regs_t *)i2c);
}

void MXC_I2C_AbortAsync(mxc_i2c_regs_t *i2c)
{
    MXC_I2C_RevA_AbortAsync((mxc_i2c_reva_regs_t *)i2c);
}

void MXC_I2C_AsyncHandler(mxc_i2c_regs_t *i2c)
{
    MXC_I2C_RevA_AsyncHandler((mxc_i2c_reva_regs_t *)i2c, interruptCheck);
}

void MXC_I2C_DMACallback(int ch, int error)
{
    MXC_I2C_RevA_DMACallback(ch, error);
}
