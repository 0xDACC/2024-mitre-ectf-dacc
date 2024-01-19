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
 * @brief   Paralel Camera Interface!
 *
 * @details This example uses the UART to print to a the image that capture by camera
 */

/***** Includes *****/
#include <stdio.h>
#include <stdint.h>

#include <MAX32xxx.h>

#include "camera.h"
#include "utils.h"

void process_img(void)
{
    uint8_t *raw;
    uint32_t imgLen;
    uint32_t w, h;

    camera_get_image(&raw, &imgLen, &w, &h);

    utils_send_img_to_pc(raw, imgLen, w, h, camera_get_pixel_format());

    /* ... */
}

// *****************************************************************************
int main(void)
{
    int ret = 0;
    printf("\n************** Parallel Camera Interface Example !*************");
    printf("\n* EvKit RevA Requires Pull-up resistor for I2C line *");
    printf("\n* Remove R22 on EvKit RevA*");
    printf("\n* Connect P1.11 to P1.20!*");
    printf("\n* UART0 is used to debug");
    printf("\n* UART1 is used to send image bytes to pc\n");

    // enable catch
    MXC_ICC_Enable();

    // To send image to PC
    MXC_UART_Init(MXC_UART1, 460800);

    camera_init();
    printf("Camera Slave Addr: 0x%X\n", camera_get_id());
    camera_dump_registers();

    camera_start_campture_image();

    while (1) {
        if (camera_is_image_rcv()) {
            process_img();
            utils_delay_ms(2000);
            camera_start_campture_image();
        }
    }

    return ret;
}
