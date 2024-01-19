/**
 * @file    i2c_revb.h
 * @brief   Inter-integrated circuit (I2C_REVB) communications interface driver.
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

#ifndef LIBRARIES_PERIPHDRIVERS_SOURCE_I2C_I2C_REVB_H_
#define LIBRARIES_PERIPHDRIVERS_SOURCE_I2C_I2C_REVB_H_

#include <stdint.h>
#include "i2c.h"
#include "i2c_reva.h"
#include "i2c_revb_regs.h"
#include "mxc_sys.h"

/* **** Definitions **** */
#define MXC_I2C_REVB_MAX_ADDR_WIDTH 0x7F
#define MXC_I2C_REVB_STD_MODE 100000
#define MXC_I2C_REVB_FAST_SPEED 400000
#define MXC_I2C_REVB_FASTPLUS_SPEED 1000000
#define MXC_I2C_REVB_HS_MODE 3400000

#define MXC_I2C_REVB_INTFL0_MASK 0x00FFFFFF
#define MXC_I2C_REVB_INTFL1_MASK 0x00000007

#define MXC_I2C_REVB_MAX_FIFO_TRANSACTION 256

#define MXC_I2C_REVB_ERROR                                            \
    (MXC_F_I2C_REVB_INT_FL0_ARBERI | MXC_F_I2C_REVB_INT_FL0_TOERI |   \
     MXC_F_I2C_REVB_INT_FL0_ADRERI | MXC_F_I2C_REVB_INT_FL0_DATAERI | \
     MXC_F_I2C_REVB_INT_FL0_DNRERI | MXC_F_I2C_REVB_INT_FL0_STRTERI | \
     MXC_F_I2C_REVB_INT_FL0_STOPERI)

typedef struct _i2c_revb_req_t mxc_i2c_revb_req_t;
typedef int (*mxc_i2c_revb_getAck_t)(mxc_i2c_revb_regs_t *i2c, unsigned char byte);
typedef void (*mxc_i2c_revb_complete_cb_t)(mxc_i2c_revb_req_t *req, int result);
typedef void (*mxc_i2c_revb_dma_complete_cb_t)(int len, int result);
struct _i2c_revb_req_t {
    mxc_i2c_revb_regs_t *i2c;
    unsigned int addr;
    unsigned char *tx_buf;
    unsigned int tx_len;
    unsigned char *rx_buf;
    unsigned int rx_len;
    int restart;
    mxc_i2c_revb_complete_cb_t callback;
};
typedef enum {
    MXC_I2C_REVB_EVT_MASTER_WR,
    MXC_I2C_REVB_EVT_MASTER_RD,
    MXC_I2C_REVB_EVT_RX_THRESH,
    MXC_I2C_REVB_EVT_TX_THRESH,
    MXC_I2C_REVB_EVT_TRANS_COMP,
    MXC_I2C_REVB_EVT_UNDERFLOW,
    MXC_I2C_REVB_EVT_OVERFLOW,
} mxc_i2c_revb_slave_event_t;
typedef int (*mxc_i2c_revb_slave_handler_t)(mxc_i2c_revb_regs_t *i2c,
                                            mxc_i2c_revb_slave_event_t event, void *data);
/* **** Variable Declaration **** */

/* **** Function Prototypes **** */

/* ************************************************************************* */
/* Control/Configuration functions                                           */
/* ************************************************************************* */
int MXC_I2C_RevB_Init(mxc_i2c_revb_regs_t *i2c, int masterMode, unsigned int slaveAddr);

int MXC_I2C_RevB_SetSlaveAddr(mxc_i2c_revb_regs_t *i2c, unsigned int slaveAddr, int idx);
int MXC_I2C_RevB_Shutdown(mxc_i2c_revb_regs_t *i2c);
int MXC_I2C_RevB_SetFrequency(mxc_i2c_revb_regs_t *i2c, unsigned int hz);
unsigned int MXC_I2C_RevB_GetFrequency(mxc_i2c_revb_regs_t *i2c);
int MXC_I2C_RevB_ReadyForSleep(mxc_i2c_revb_regs_t *i2c);
int MXC_I2C_RevB_SetClockStretching(mxc_i2c_revb_regs_t *i2c, int enable);
int MXC_I2C_RevB_GetClockStretching(mxc_i2c_revb_regs_t *i2c);

/* ************************************************************************* */
/* Low-level functions                                                       */
/* ************************************************************************* */
int MXC_I2C_RevB_Start(mxc_i2c_revb_regs_t *i2c);
int MXC_I2C_RevB_Stop(mxc_i2c_revb_regs_t *i2c);
int MXC_I2C_RevB_WriteByte(mxc_i2c_revb_regs_t *i2c, unsigned char byte);
int MXC_I2C_RevB_ReadByte(mxc_i2c_revb_regs_t *i2c, unsigned char *byte, int ack);
int MXC_I2C_RevB_ReadByteInteractive(mxc_i2c_revb_regs_t *i2c, unsigned char *byte,
                                     mxc_i2c_revb_getAck_t getAck);
int MXC_I2C_RevB_Write(mxc_i2c_revb_regs_t *i2c, unsigned char *bytes, unsigned int *len);
int MXC_I2C_RevB_Read(mxc_i2c_revb_regs_t *i2c, unsigned char *bytes, unsigned int *len, int ack);
int MXC_I2C_RevB_ReadRXFIFO(mxc_i2c_revb_regs_t *i2c, volatile unsigned char *bytes,
                            unsigned int len);
int MXC_I2C_RevB_ReadRXFIFODMA(mxc_i2c_revb_regs_t *i2c, unsigned char *bytes, unsigned int len,
                               mxc_i2c_revb_dma_complete_cb_t callback, mxc_dma_config_t config,
                               mxc_dma_regs_t *dma);
int MXC_I2C_RevB_GetRXFIFOAvailable(mxc_i2c_revb_regs_t *i2c);
int MXC_I2C_RevB_WriteTXFIFO(mxc_i2c_revb_regs_t *i2c, volatile unsigned char *bytes,
                             unsigned int len);
int MXC_I2C_RevB_WriteTXFIFODMA(mxc_i2c_revb_regs_t *i2c, unsigned char *bytes, unsigned int len,
                                mxc_i2c_revb_dma_complete_cb_t callback, mxc_dma_config_t config,
                                mxc_dma_regs_t *dma);
int MXC_I2C_RevB_GetTXFIFOAvailable(mxc_i2c_revb_regs_t *i2c);
void MXC_I2C_RevB_ClearRXFIFO(mxc_i2c_revb_regs_t *i2c);
void MXC_I2C_RevB_ClearTXFIFO(mxc_i2c_revb_regs_t *i2c);
int MXC_I2C_RevB_GetFlags(mxc_i2c_revb_regs_t *i2c, unsigned int *flags0, unsigned int *flags1);
void MXC_I2C_RevB_ClearFlags(mxc_i2c_revb_regs_t *i2c, unsigned int flags0, unsigned int flags1);
void MXC_I2C_RevB_EnableInt(mxc_i2c_revb_regs_t *i2c, unsigned int flags0, unsigned int flags1);
void MXC_I2C_RevB_DisableInt(mxc_i2c_revb_regs_t *i2c, unsigned int flags0, unsigned int flags1);
void MXC_I2C_RevB_EnablePreload(mxc_i2c_revb_regs_t *i2c);
void MXC_I2C_RevB_DisablePreload(mxc_i2c_revb_regs_t *i2c);
void MXC_I2C_RevB_EnableGeneralCall(mxc_i2c_revb_regs_t *i2c);
void MXC_I2C_RevB_DisableGeneralCall(mxc_i2c_revb_regs_t *i2c);
void MXC_I2C_RevB_SetTimeout(mxc_i2c_revb_regs_t *i2c, unsigned int timeout);
unsigned int MXC_I2C_RevB_GetTimeout(mxc_i2c_revb_regs_t *i2c);
int MXC_I2C_RevB_Recover(mxc_i2c_revb_regs_t *i2c, unsigned int retries);

/* ************************************************************************* */
/* Transaction level functions                                               */
/* ************************************************************************* */
int MXC_I2C_RevB_MasterTransaction(mxc_i2c_revb_req_t *req);
int MXC_I2C_RevB_MasterTransactionAsync(mxc_i2c_revb_req_t *req);
int MXC_I2C_RevB_MasterTransactionDMA(mxc_i2c_revb_req_t *req, mxc_dma_regs_t *dma);
int MXC_I2C_RevB_SlaveTransaction(mxc_i2c_revb_regs_t *i2c, mxc_i2c_revb_slave_handler_t callback,
                                  uint32_t interruptCheck);
int MXC_I2C_RevB_SlaveTransactionAsync(mxc_i2c_revb_regs_t *i2c,
                                       mxc_i2c_revb_slave_handler_t callback,
                                       uint32_t interruptCheck);
int MXC_I2C_RevB_SetRXThreshold(mxc_i2c_revb_regs_t *i2c, unsigned int numBytes);
unsigned int MXC_I2C_RevB_GetRXThreshold(mxc_i2c_revb_regs_t *i2c);
int MXC_I2C_RevB_SetTXThreshold(mxc_i2c_revb_regs_t *i2c, unsigned int numBytes);
unsigned int MXC_I2C_RevB_GetTXThreshold(mxc_i2c_revb_regs_t *i2c);
void MXC_I2C_RevB_AsyncCallback(mxc_i2c_revb_regs_t *i2c, int retVal);
void MXC_I2C_RevB_AsyncStop(mxc_i2c_revb_regs_t *i2c);
void MXC_I2C_RevB_AbortAsync(mxc_i2c_revb_regs_t *i2c);
void MXC_I2C_RevB_MasterAsyncHandler(int i2cNum);
unsigned int MXC_I2C_RevB_SlaveAsyncHandler(mxc_i2c_revb_regs_t *i2c,
                                            mxc_i2c_revb_slave_handler_t callback,
                                            unsigned int interruptEnables, int *retVal);
void MXC_I2C_RevB_AsyncHandler(mxc_i2c_revb_regs_t *i2c, uint32_t interruptCheck);
void MXC_I2C_RevB_DMACallback(int ch, int error);

#endif // LIBRARIES_PERIPHDRIVERS_SOURCE_I2C_I2C_REVB_H_
