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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "mxc.h"
#include "cnn.h"
#include "mxc_delay.h"
#include "led.h"
#include "camera.h"
#include "camera_util.h"
#ifdef BOARD_EVKIT_V1
#include "bitmap.h"
#include "tft_ssd2119.h"
#endif
#ifdef BOARD_FTHR_REVA
#include "tft_ili9341.h"
#endif
#include "sampledata.h"

#define USE_CAMERA // if enabled, it uses the camera specified in the make file, otherwise it uses serial loader

#ifdef BOARD_EVKIT_V1
int font = urw_gothic_12_grey_bg_white;
#endif
#ifdef BOARD_FTHR_REVA
int font = (int)&SansSerif16x16[0];
#endif

volatile uint32_t cnn_time; // Stopwatch

#define CON_BAUD 115200
#define NUM_PIXELS 7744 // 88x88
#define NUM_IN_CHANNLES 48
#define NUM_OUT_CHANNLES 32
#define INFER_SIZE 30976 // size of inference 32x88x88/8
#define TFT_BUFF_SIZE 50 // TFT buffer size

uint32_t cnn_out_packed[INFER_SIZE / 8];
uint8_t cnn_out_unfolded[INFER_SIZE / 2];

void fail(void)
{
    printf("\n*** FAIL ***\n\n");

    while (1) {}
}

// 48-channel 88x88 data input (371712 bytes total / 7744 bytes per channel):
// HWC 88x88, channels 0 to 3
/*static const uint32_t input_0[] = SAMPLE_INPUT_0;

// HWC 88x88, channels 4 to 7
static const uint32_t input_4[] = SAMPLE_INPUT_4;

// HWC 88x88, channels 8 to 11
static const uint32_t input_8[] = SAMPLE_INPUT_8;

// HWC 88x88, channels 12 to 15
static const uint32_t input_12[] = SAMPLE_INPUT_12;

// HWC 88x88, channels 16 to 19
static const uint32_t input_16[] = SAMPLE_INPUT_16;

// HWC 88x88, channels 20 to 23
static const uint32_t input_20[] = SAMPLE_INPUT_20;

// HWC 88x88, channels 24 to 27
static const uint32_t input_24[] = SAMPLE_INPUT_24;

// HWC 88x88, channels 28 to 31
static const uint32_t input_28[] = SAMPLE_INPUT_28;

// HWC 88x88, channels 32 to 35
static const uint32_t input_32[] = SAMPLE_INPUT_32;

// HWC 88x88, channels 36 to 39
static const uint32_t input_36[] = SAMPLE_INPUT_36;

// HWC 88x88, channels 40 to 43
static const uint32_t input_40[] = SAMPLE_INPUT_40;

// HWC 88x88, channels 44 to 47
static const uint32_t input_44[] = SAMPLE_INPUT_44;*/

int console_UART_init(uint32_t baud)
{
    mxc_uart_regs_t *ConsoleUart = MXC_UART_GET_UART(CONSOLE_UART);
    int err;
    NVIC_ClearPendingIRQ(MXC_UART_GET_IRQ(CONSOLE_UART));
    NVIC_DisableIRQ(MXC_UART_GET_IRQ(CONSOLE_UART));
    NVIC_SetPriority(MXC_UART_GET_IRQ(CONSOLE_UART), 1);
    NVIC_EnableIRQ(MXC_UART_GET_IRQ(CONSOLE_UART));

    if ((err = MXC_UART_Init(ConsoleUart, baud, MXC_UART_IBRO_CLK)) != E_NO_ERROR) {
        return err;
    }

    return 0;
}

uint8_t gen_crc(const void *vptr, int len)
{
    const uint8_t *data = vptr;
    unsigned crc = 0;
    int i, j;

    for (j = len; j; j--, data++) {
        crc ^= (*data << 8);

        for (i = 8; i; i--) {
            if (crc & 0x8000) {
                crc ^= (0x1070 << 3);
            }

            crc <<= 1;
        }
    }

    return (uint8_t)(crc >> 8);
}

static void console_uart_send_byte(uint8_t value)
{
    while (MXC_UART_WriteCharacter(MXC_UART_GET_UART(CONSOLE_UART), value) == E_OVERFLOW) {}
}

static void console_uart_send_bytes(uint8_t *ptr, int length)
{
    int i;

    for (i = 0; i < length; i++) {
        console_uart_send_byte(ptr[i]);
        //printf("%d\n", ptr[i]);
    }
}

void load_input_serial(void)
{
    uint32_t in_data[NUM_PIXELS];
    uint8_t rxdata[4];
    uint32_t tmp;
    uint8_t crc, crc_result;
    uint32_t index = 0;
    LED_Off(LED2);

    printf("READY\n");

    uint32_t *data_addr = (uint32_t *)0x50400700;

    for (int ch = 0; ch < NUM_IN_CHANNLES; ch += 4) {
        LED_Toggle(LED1);

        for (int i = 0; i < NUM_PIXELS; i++) {
            index++;
            tmp = 0;

            for (int j = 0; j < 4; j++) {
                rxdata[j] = MXC_UART_ReadCharacter(MXC_UART_GET_UART(CONSOLE_UART));
                tmp = tmp | (rxdata[j] << 8 * (3 - j));
            }

            //read crc
            crc = MXC_UART_ReadCharacter(MXC_UART_GET_UART(CONSOLE_UART));
            crc_result = gen_crc(rxdata, 4);

            if (crc != crc_result) {
                printf("E %d", index);
                LED_On(LED2);

                while (1) {}
            }

            //fill input buffer
            in_data[i] = tmp;
        }

        // load data to cnn
        memcpy32(data_addr, in_data, NUM_PIXELS);
        // printf("%d- %08X \n",ch,data_addr);
        data_addr += 0x2000;

        if ((data_addr == (uint32_t *)0x50420700) || (data_addr == (uint32_t *)0x50820700) ||
            (data_addr == (uint32_t *)0x50c20700)) {
            data_addr += 0x000f8000;
        }
    }

    /*
     Data Order:
     camera data: (352,352,3), following indexes are based on camera pixel index

     0x50400700:
        (0,1,0)|(0,0,2)|(0,0,1)|(0,0,0)              // 0
        (0,5,0)|(0,4,2)|(0,4,1)|(0,4,0)              // 1
        ...
        (0,349,0)|(0,348,2)|(0,348,1)|(0,348,0)      // 87

        (4,1,0)|(4,0,2)|(4,0,1)|(4,0,0)              // 88
        (4,5,0)|(4,4,2)|(4,4,1)|(4,4,0)
        ...
        (4,349,0)|(4,348,2)|(4,348,1)|(4,348,0)       // 175
        ...
        ...
        ...
        (348,1,0)|(348,0,2)|(348,0,1)|(348,0,0)              //
        (348,5,0)|(348,4,2)|(348,4,1)|(348,4,0)
        ...
        (348,349,0)|(348,348,2)|(348,348,1)|(348,348,0)       // 7743

     0x50408700:
            (0,2,1)|(0,2,0)|(0,1,2)|(0,1,1)              // 0
        (0,6,1)|(0,6,0)|(0,5,2)|(0,5,1)              // 1
        ...
        (0,350,1)|(0,350,0)|(0,349,2)|(0,349,1)      // 87

        (4,2,1)|(4,2,0)|(4,1,2)|(4,1,1)              // 88
        (4,6,1)|(4,6,0)|(4,5,2)|(4,5,1)
        ...
        (4,350,1)|(4,350,0)|(4,349,2)|(4,349,1)      // 175
        ...
        ...
        ...
        (348,2,1)|(348,2,0)|(348,1,2)|(348,1,1)              //
        (348,6,1)|(348,6,0)|(348,5,2)|(348,5,1)
        ...
        (348,350,1)|(348,350,0)|(348,349,2)|(348,349,1)      // 7743

     0x50410700:
            (0,3,2)|(0,3,1)|(0,3,0)|(0,2,2)              // 0
        (0,7,2)|(0,7,1)|(0,7,0)|(0,6,2)              // 1
        ...
        (0,351,2)|(0,351,1)|(0,351,0)|(0,350,2)      // 87

        ...
        ...
        ...
        (348,3,2)|(348,3,1)|(348,3,0)|(348,2,2)              //
        (348,7,2)|(348,7,1)|(348,7,0)|(348,6,2)
        ...
        (348,351,2)|(348,351,1)|(348,351,0)|(348,350,2)      // 7743


    The same pattern of 3x7744 words repeats another 3 times, with starting row index changed from 0 to 1, then 2 and then 3
    resulting in 4x3x7744 words:
    ....
      0x50c18700: last bank
      ...
        (351,351,2)|(351,351,1)|(351,351,0)|(351,350,2)      // 7743


      */

    // This function loads the sample data input -- replace with actual data

    /*
    memcpy32((uint32_t *) 0x50400700, input_0, 7744);
    memcpy32((uint32_t *) 0x50408700, input_4, 7744);
    memcpy32((uint32_t *) 0x50410700, input_8, 7744);
    memcpy32((uint32_t *) 0x50418700, input_12, 7744);
    memcpy32((uint32_t *) 0x50800700, input_16, 7744);
    memcpy32((uint32_t *) 0x50808700, input_20, 7744);
    memcpy32((uint32_t *) 0x50810700, input_24, 7744);
    memcpy32((uint32_t *) 0x50818700, input_28, 7744);
    memcpy32((uint32_t *) 0x50c00700, input_32, 7744);
    memcpy32((uint32_t *) 0x50c08700, input_36, 7744);
    memcpy32((uint32_t *) 0x50c10700, input_40, 7744);
    memcpy32((uint32_t *) 0x50c18700, input_44, 7744);
    */
}

// Expected output of layer 18 for unet_v7_binary given the sample input (known-answer test)
// Delete this function for production code
//static const uint32_t sample_output[] = SAMPLE_OUTPUT;
int check_output(void)
{
    int i;
    uint32_t mask, len;
    volatile uint32_t *addr;
    const uint32_t *ptr = 0; //sample_output;

    while ((addr = (volatile uint32_t *)*ptr++) != 0) {
        mask = *ptr++;
        len = *ptr++;

        for (i = 0; i < len; i++)
            if ((*addr++ & mask) != *ptr++) {
                return CNN_FAIL;
            }
    }

    return CNN_OK;
}

void send_output(void)
{
    uint8_t *data_addr = (uint8_t *)0x50400000;

    printf("SENDING_OUTPUT\n");

    for (int ch = 0; ch < NUM_OUT_CHANNLES; ch += 4) {
        console_uart_send_bytes(data_addr, 4 * NUM_PIXELS);
        data_addr += 0x8000;

        if ((data_addr == (uint8_t *)0x50420000) || (data_addr == (uint8_t *)0x50820000) ||
            (data_addr == (uint8_t *)0x50c20000)) {
            data_addr += 0x003e0000;
        }
    }
}

void cnn_unload_packed(uint32_t *p_out)
{
    uint32_t buf;
    uint8_t *data_addr = (uint8_t *)0x50400000;
    uint8_t temp, a, b;

    for (int j = 0; j < 8; j++) { // 8 data blocks
        for (int i = 0; i < 1936; i += 4) { //packing bits into one byte  352x88/16=30976/16=1936
            buf = 0;

            for (int n = 0; n < 4; n++) {
                //0
                int val = (i + n) * 16;
                temp = 0;
                a = ((*(data_addr + 0 + val)) ^ 0x80);
                b = ((*(data_addr + 1 + val)) ^ 0x80);
                // Compare CNN outputs and set bit
                temp += ((a > b) ? 0 : 1) << 7;

                //1
                a = ((*(data_addr + 2 + val)) ^ 0x80);
                b = ((*(data_addr + 3 + val)) ^ 0x80);
                temp += ((a > b) ? 0 : 1) << 6;

                //2
                a = ((*(data_addr + 4 + val)) ^ 0x80);
                b = ((*(data_addr + 5 + val)) ^ 0x80);
                temp += ((a > b) ? 0 : 1) << 5;

                //3
                a = ((*(data_addr + 6 + val)) ^ 0x80);
                b = ((*(data_addr + 7 + val)) ^ 0x80);
                temp += ((a > b) ? 0 : 1) << 4;

                //4
                a = ((*(data_addr + 8 + val)) ^ 0x80);
                b = ((*(data_addr + 9 + val)) ^ 0x80);
                temp += ((a > b) ? 0 : 1) << 3;

                //5
                a = ((*(data_addr + 10 + val)) ^ 0x80);
                b = ((*(data_addr + 11 + val)) ^ 0x80);
                temp += ((a > b) ? 0 : 1) << 2;

                //6
                a = ((*(data_addr + 12 + val)) ^ 0x80);
                b = ((*(data_addr + 13 + val)) ^ 0x80);
                temp += ((a > b) ? 0 : 1) << 1;

                //7
                a = ((*(data_addr + 14 + val)) ^ 0x80);
                b = ((*(data_addr + 15 + val)) ^ 0x80);
                temp += ((a > b) ? 0 : 1);

                // Construct 32-bit word
                buf |= temp << (8 * n);
            }

            // Store packed 32-bit word
            *p_out++ = buf;
        }

        data_addr += 0x8000;

        if ((data_addr == (uint8_t *)0x50420000) || (data_addr == (uint8_t *)0x50820000) ||
            (data_addr == (uint8_t *)0x50c20000)) {
            data_addr += 0x003e0000;
        }
    }
}

void write_TFT_pixel(int row, int col, unsigned char value)
{
    int color;
    uint8_t r, g, b;

    // Only display mask in TFT limits
    if ((col >= TFT_W) || (row >= TFT_H)) {
        return;
    }

#ifdef USE_CAMERA
    if (value == 1) {
        //set blue background color for value=1
        r = 0;
        g = 0;
        b = 255;
#else
    if (value == 0) {
        //set white portrait color for value=0
        r = 255;
        g = 255;
        b = 255;
#endif
#ifdef BOARD_EVKIT_V1
        color =
            (0x01000100 | ((b & 0xF8) << 13) | ((g & 0x1C) << 19) | ((g & 0xE0) >> 5) | (r & 0xF8));
#endif
#ifdef BOARD_FTHR_REVA
        color = RGB(r, g, b); // convert to RGB565
#endif
        MXC_TFT_WritePixel(col, row, 1, 1, color);
    }
}

void unfold_display_packed(unsigned char *in_buff, unsigned char *out_buff)
{
    int index = 0;
    unsigned char temp[2];

    for (int r = 0; r < 88; r++) {
        for (int c = 0; c < 8; c++) {
            int idx = 22 * r + 88 * 22 * c;

            for (int d = 0; d < 22; d++) {
                out_buff[index + d] = in_buff[idx + d];
            }

            index += 22;
        }
    }

    for (int s1 = 0; s1 < 352; s1++) {
        for (int s2 = 0; s2 < 22; s2++) {
            temp[0] = out_buff[s1 * 44 + s2 + 00];
            temp[1] = out_buff[s1 * 44 + s2 + 22];

            // extract bit per pixel from packed bytes
            write_TFT_pixel(s1, (0 + 16 * s2), (temp[0] & 0x80) >> 7);
            write_TFT_pixel(s1, (1 + 16 * s2), (temp[1] & 0x80) >> 7);
            write_TFT_pixel(s1, (2 + 16 * s2), (temp[0] & 0x40) >> 6);
            write_TFT_pixel(s1, (3 + 16 * s2), (temp[1] & 0x40) >> 6);

            write_TFT_pixel(s1, (4 + 16 * s2), (temp[0] & 0x20) >> 5);
            write_TFT_pixel(s1, (5 + 16 * s2), (temp[1] & 0x20) >> 5);
            write_TFT_pixel(s1, (6 + 16 * s2), (temp[0] & 0x10) >> 4);
            write_TFT_pixel(s1, (7 + 16 * s2), (temp[1] & 0x10) >> 4);

            write_TFT_pixel(s1, (8 + 16 * s2), (temp[0] & 0x08) >> 3);
            write_TFT_pixel(s1, (9 + 16 * s2), (temp[1] & 0x08) >> 3);
            write_TFT_pixel(s1, (10 + 16 * s2), (temp[0] & 0x04) >> 2);
            write_TFT_pixel(s1, (11 + 16 * s2), (temp[1] & 0x04) >> 2);

            write_TFT_pixel(s1, (12 + 16 * s2), (temp[0] & 0x02) >> 1);
            write_TFT_pixel(s1, (13 + 16 * s2), (temp[1] & 0x02) >> 1);
            write_TFT_pixel(s1, (14 + 16 * s2), (temp[0] & 0x01) >> 0);
            write_TFT_pixel(s1, (15 + 16 * s2), (temp[1] & 0x01) >> 0);
        }
    }
}

void TFT_Print(char *str, int x, int y, int font, int length)
{
    // fonts id
    text_t text;
    text.data = str;
    text.len = length;

    MXC_TFT_PrintFont(x, y, font, &text, NULL);
}

int main(void)
{
    char buff[TFT_BUFF_SIZE];

#if defined(BOARD_FTHR_REVA)
    // Wait for PMIC 1.8V to become available, about 180ms after power up.
    MXC_Delay(200000);
    /* Enable camera power */
    Camera_Power(POWER_ON);
    printf("\n\nPortrait Segmentation Feather Demo\n");
#else
    printf("\n\nPortrait Segmentation Evkit Demo\n");
#endif
    MXC_ICC_Enable(MXC_ICC0); // Enable cache

    // Switch to 100 MHz clock
    MXC_SYS_Clock_Select(MXC_SYS_CLOCK_IPO);
    SystemCoreClockUpdate();

    // Initialize UART
    console_UART_init(CON_BAUD);

#ifdef USE_CAMERA
    initialize_camera();
    //run_camera();
#else
    printf("Start SerialLoader.py script...\n");
#endif

    // Initialize TFT display.
    printf("Init TFT\n");
#ifdef BOARD_EVKIT_V1
    MXC_TFT_Init();
#endif
#ifdef BOARD_FTHR_REVA
    MXC_TFT_Init(MXC_SPI0, 1, NULL, NULL);
    MXC_TFT_SetRotation(ROTATE_270);
    MXC_TFT_SetForeGroundColor(WHITE); // set chars to white
    MXC_TFT_SetBackGroundColor(BLACK);

#endif
    memset(buff, 32, TFT_BUFF_SIZE);
    TFT_Print(buff, 55, 30, font, snprintf(buff, sizeof(buff), "ANALOG DEVICES             "));
    TFT_Print(buff, 15, 50, font, snprintf(buff, sizeof(buff), "Portrait Segmentation Demo      "));
    TFT_Print(buff, 120, 90, font, snprintf(buff, sizeof(buff), "Ver. 1.0.0                   "));
    MXC_Delay(SEC(2));
    MXC_TFT_ClearScreen();
#ifdef BOARD_EVKIT_V1
    MXC_TFT_SetBackGroundColor(255);
#endif
    // Enable peripheral, enable CNN interrupt, turn on CNN clock
    // CNN clock: 50 MHz div 1
    cnn_enable(MXC_S_GCR_PCLKDIV_CNNCLKSEL_PCLK, MXC_S_GCR_PCLKDIV_CNNCLKDIV_DIV1);
    cnn_boost_enable(MXC_GPIO2, MXC_GPIO_PIN_5); // Turn on the boost circuit
    cnn_init(); // Bring state machine into consistent state
    cnn_load_weights(); // Load kernels
    cnn_load_bias();
    cnn_configure(); // Configure state machine

#ifdef USE_CAMERA
    // Start getting images from camera and processing them
    printf("Start capturing\n");
    camera_start_capture_image();
#endif

    while (1) {
        LED_Toggle(LED1);

#ifndef USE_CAMERA
        load_input_serial(); // Load data input from serial port
#else
        load_input_camera(); // Load data input from camera
#endif

#ifdef PATTERN_GEN
        //dump_cnn();
#endif

        // start inference
#ifdef USE_CAMERA
        camera_start_capture_image(); // next frame
#endif
        cnn_start(); // Start CNN processing

#ifdef USE_CAMERA
        printf("Display image\n");
        display_camera();
        MXC_Delay(SEC(1));
#endif

        SCB->SCR &= ~SCB_SCR_SLEEPDEEP_Msk; // SLEEPDEEP=0

        while (cnn_time == 0) {
            __WFI(); // Wait for CNN
        }

        // unload
        //dump_inference();

        printf("Display mask\n");
        cnn_unload_packed(cnn_out_packed);
        unfold_display_packed((unsigned char *)cnn_out_packed, cnn_out_unfolded);

#ifndef USE_CAMERA
        send_output(); // send CNN output to UART
#endif
        MXC_Delay(SEC(1));

#ifdef USE_CAMERA
        camera_start_capture_image();
#endif

        if (PB_Get(0)) {
#ifdef CNN_INFERENCE_TIMER
            printf("\n*** Approximate inference time: %u us ***\n\n", cnn_time);
#endif
        }
    }
}
