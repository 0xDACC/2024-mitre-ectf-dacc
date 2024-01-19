/*******************************************************************************
* Copyright (C) Maxim Integrated Products, Inc., All Rights Reserved.
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

/**
 * @file    main.c
 * @brief   Hello World!
 *
 * @details This example uses the UART to print to a terminal and flashes an LED(P2.17).
 */

/***** Includes *****/
#include <stdio.h>
#include <stdint.h>

#include <MAX32xxx.h>

/***** Definitions *****/

/***** Globals *****/

/***** Functions *****/
void Test1()
{
    uint32_t flags = MXC_SMON_GetFlags();

    flags = flags & MXC_F_SMON_SECALM_EXTSWARN1;

    printf("\n\nAlarm Flags Before Error: 0x%x", flags);

    mxc_smon_ext_cfg_t cfg;

    cfg.sensorNumber = SMON_EXTSENSOR_1;
    cfg.clockDivide = SMON_CLK_DIVIDE_1;
    cfg.freqDivide = SMON_FREQ_DIVIDE_4;
    cfg.errorCount = 1;

    MXC_SMON_ExtSensorEnable(&cfg, 5000);

    flags = 0x00;

    while (!(flags)) {
        flags = MXC_SMON_GetFlags() & MXC_F_SMON_SECALM_EXTSWARN1;
    }

    printf("\nAlarm Flags After Error: 0x%x\n", flags);

    MXC_SMON_ClearFlags(MXC_F_SMON_SECALM_EXTSWARN1);
}

void Test2()
{
    uint32_t flags = MXC_SMON_GetFlags();

    flags = flags & MXC_F_SMON_SECALM_EXTSWARN0;

    printf("\n\nAlarm Flags Before Error: 0x%x", flags);

    mxc_smon_ext_cfg_t cfg;

    cfg.sensorNumber = SMON_EXTSENSOR_0;
    cfg.clockDivide = SMON_CLK_DIVIDE_1;
    cfg.freqDivide = SMON_FREQ_DIVIDE_4;
    cfg.data = 0x51;
    cfg.errorCount = 1;

    MXC_SMON_SelfDestructByteEnable(&cfg, 5000);
    printf("\nData before Error: 0x%x\n", (MXC_SMON->sdbe & MXC_F_SMON_SDBE_DBYTE));

    flags = 0x00;

    while (!(flags)) {
        flags = MXC_SMON_GetFlags() & MXC_F_SMON_SECALM_EXTSWARN0;
    }

    printf("\nAlarm Flags After Error: 0x%x", flags);
    printf("\nData: 0x%x\n", MXC_SMON->sdbe & MXC_F_SMON_SDBE_DBYTE);

    MXC_SMON_ClearFlags(MXC_F_SMON_SECALM_EXTSWARN0);
}

// *****************************************************************************
int main(void)
{
    printf("\n***********Hello World!***********\n");
    printf("\nConnect the jumper between output and input\n");
    printf("pins of External Sensor 0 and External Sensor 1.\n");
    printf("To cause sensor error you will have to remove\n");
    printf("the jumper after initialization.\n");

    MXC_SMON_Init();

    printf("\nExternal Sensor 1 Enabled\n");
    printf("Remove Jumper on Sensor 1 to cause sensor 1 warning");
    Test1();

    printf("\n\nSelf Destruct Byte Enabled for External Sensor 0\n");
    printf("Remove Jumper on Sensor 0 to destroy the byte");
    Test2();

    printf("\nExample Completed\n\n");
    return E_NO_ERROR;
}
