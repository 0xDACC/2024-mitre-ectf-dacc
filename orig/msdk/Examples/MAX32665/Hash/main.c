/**
 * @file        main.c
 * @brief       Hash Example
 * @details
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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mxc_device.h"
#include "max32665.h"
#include "board.h"
#include "tpu.h"

/***** Globals *****/

char temp[] = { 0x00, 0x00, 0x00 };

void ascii_to_byte(const char *src, char *dst, int len)
{
    int i;
    for (i = 0; i < len; ++i) {
        int val;
        temp[0] = *src;
        src++;
        temp[1] = *src;
        src++;
        sscanf(temp, "%0x", &val);
        dst[i] = val;
    }
}

int Test_Hash(void)
{
    int ret;
    printf("Test Hash\n");

    unsigned char sha256_msg[] =
        "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890!@#$%&*()";

    char _sha256_result[] = "93bfb2299f7427f021ad038cec5054b4db2e935f3ae10d64e4e6a40a77269803";
    char sha256_result[33];
    ascii_to_byte(_sha256_result, sha256_result, 32);

    unsigned char destination[33];
    unsigned int msgLen = sizeof(sha256_msg) - 1;

    memset(destination, 0, sizeof(destination));

    // Reset Crypto Block
    MXC_TPU_Init(MXC_SYS_PERIPH_CLOCK_TPU);

    // Select the Hash Function
    MXC_TPU_Hash_Config(MXC_TPU_HASH_SHA256);

    MXC_TPU_Hash_SHA((char *)sha256_msg, MXC_TPU_HASH_SHA256, msgLen, (char *)destination);

    MXC_TPU_Shutdown(MXC_SYS_PERIPH_CLOCK_TPU);

    if (memcmp(sha256_result, destination, 32)) {
        printf(" * Failed *\n\n");
        return -1;
    }

    printf("   Passed  \n\n");
    return 0;
}

int main(void)
{
    printf("\n\n********** CTB Hash Example **********\n\n");

    int fail = 0;
    fail += Test_Hash();

    if (fail != 0) {
        printf("\nExample Failed\n");
        return E_FAIL;
    }

    printf("\nExample Succeeded\n");
    return E_NO_ERROR;
}
