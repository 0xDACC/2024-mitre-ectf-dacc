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

/**
 * @file    main.c
 * @brief   Parallel camera example for the HM0360-AWA Bayer camera sensors as defined in the makefile.
 *
 * @details This example uses the UART to stream out the image captured from the camera.
 *          Alternatively, it can display the captured image on TFT if it is enabled with  the 
 *          TFT_ENABLE compiler definition.
 *          The image is prepended with a header that is interpreted by the grab_image.py
 *          python script.  The data from this example through the UART is in a binary format.
 *          Instructions: 1) Load and execute this example. The example will initialize the camera
 *                        and start the repeating binary output of camera frame data.
 *                        2) Run 'sudo grab_image.py /dev/ttyUSB0 921600'
 *                           Substitute the /dev/ttyUSB0 string for the serial port on your system.
 *                           The python program will read in the binary data from this example and
 *                           output a png image.
 */

/***** Includes *****/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "mxc.h"
#include "mxc_device.h"
#include "mxc_delay.h"
#include "uart.h"
#include "led.h"
#include "board.h"

#include "camera.h"
#include "utils.h"
#include "dma.h"

//------------------------
// Configuration options
//------------------------

/*
* Enables TFT display.  If this is
* disabled (commented out), then the
* firmware will send the image data
* over the serial port for use with
* pc_utility/grab_image.py
*/
// #define ENABLE_TFT

#define CAMERA_FREQ (10 * 1000 * 1000)

// Only 160x120 is currently supported.
#define IMAGE_XRES 160
#define IMAGE_YRES 120

//UART baudrate used for sending data to PC, use max 921600 for serial stream
#define CON_BAUD 115200 * 8

#define X_START 0
#define Y_START 0

typedef enum { BAYER_FUNCTION_PASSTHROUGH = 0, BAYER_FUNCTION_BILINEAR } bayer_function_t;

// Set the default debayering function here
bayer_function_t g_bayer_function = BAYER_FUNCTION_BILINEAR;

//------------------------

#ifdef ENABLE_TFT

#ifdef BOARD_EVKIT_V1
#include "tft_ssd2119.h"
#endif

#endif

static uint8_t *image_data;

void process_img(void)
{
    uint8_t *raw;
    uint32_t imgLen;
    uint32_t w, h;

    // Get the details of the image from the camera driver.
    camera_get_image(&raw, &imgLen, &w, &h);

    if (image_data) {
        switch (g_bayer_function) {
        case (BAYER_FUNCTION_PASSTHROUGH):
            bayer_passthrough(raw, w, h, (uint16_t *)image_data);
            break;
        case (BAYER_FUNCTION_BILINEAR):
            color_correct(raw, w, h);
            bayer_bilinear_demosaicing(raw, w, h, (uint16_t *)image_data);
            break;
        }

#ifdef ENABLE_TFT
        MXC_TFT_ShowImageCameraRGB565(X_START, Y_START, image_data, w, h);
#else
        /*
        * Stream image data to PC.
        * Notice the data characteristics
        * are modified here since the raw
        * data has been converted to RGB565.
        */
        utils_stream_img_to_pc_init(image_data, imgLen * 2, w, h, (uint8_t *)"RGB565");

        // Get image line by line
        for (int i = 0; i < h; i++) {
            // Send one line to PC
            utils_stream_image_row_to_pc(image_data + (i * w * 2), w * 2);
        }
#endif
    }
}

void UART_Handler(void)
{
    MXC_UART_AsyncHandler(MXC_UART_GET_UART(CONSOLE_UART));
    printf("TTY\n");
}

// *****************************************************************************
int main(void)
{
    int ret = 0;
    int slaveAddress;
    int id;
    int dma_channel;

    /* Enable cache */
    MXC_ICC_Enable(MXC_ICC0);

    /* Set system clock to 100 MHz */
    MXC_SYS_Clock_Select(MXC_SYS_CLOCK_IPO);
    SystemCoreClockUpdate();

    // Initialize DMA for camera interface
    MXC_DMA_Init();
    dma_channel = MXC_DMA_AcquireChannel();

    mxc_uart_regs_t *ConsoleUart = MXC_UART_GET_UART(CONSOLE_UART);

    if ((ret = MXC_UART_Init(ConsoleUart, CON_BAUD, MXC_UART_IBRO_CLK)) != E_NO_ERROR) {
        return ret;
    }

    // Reset Console UART
    MXC_UART_ClearRXFIFO(MXC_UART_GET_UART(CONSOLE_UART));
    NVIC_ClearPendingIRQ(MXC_UART_GET_IRQ(CONSOLE_UART));
    NVIC_DisableIRQ(MXC_UART_GET_IRQ(CONSOLE_UART));
    MXC_NVIC_SetVector(MXC_UART_GET_IRQ(CONSOLE_UART), UART_Handler);
    NVIC_EnableIRQ(MXC_UART_GET_IRQ(CONSOLE_UART));

    // Initialize the camera driver.
    camera_init(CAMERA_FREQ);
    printf("\n\nCamera Example\n");

    slaveAddress = camera_get_slave_address();
    printf("Camera I2C slave address: %02x\n", slaveAddress);

    // Obtain the manufacturer ID of the camera.
    ret = camera_get_manufacture_id(&id);

    if (ret != STATUS_OK) {
        printf("Error returned from reading camera id. Error %d\n", ret);
        return -1;
    }

    printf("Camera ID detected: %04x\n", id);

    // hmirror and vflip must be disabled for demosaicing functions to work properly
    camera_set_hmirror(0);
    camera_set_vflip(0);

#ifdef ENABLE_TFT
    printf("Init TFT\n");
    /* Initialize TFT display */
    MXC_TFT_Init();
    MXC_TFT_SetBackGroundColor(4);
#endif

    ret =
        camera_setup(IMAGE_XRES, IMAGE_YRES, PIXFORMAT_BAYER, FIFO_FOUR_BYTE, USE_DMA, dma_channel);

    if (ret != STATUS_OK) {
        printf("Error returned from setting up camera. Error %d\n", ret);
        return -1;
    }

    /*
    Allocate the memory to buffer the raw bayer image
    data received from the camera.
    */
    image_data = (uint8_t *)malloc(2 * IMAGE_XRES * IMAGE_YRES);

    MXC_Delay(SEC(1));

    // Start capturing the first image.
    printf("Starting\n");
    camera_start_capture_image();

    while (1) {
#ifndef STREAM_ENABLE
        if (camera_is_image_rcv())
#endif
        {
            // Post-process the received image.
            // See the implementation of this function
            // for debayering.
            process_img();

            // Prepare for another frame capture.
            LED_Toggle(LED1);
            camera_start_capture_image();
        }
    }

    return ret;
}
