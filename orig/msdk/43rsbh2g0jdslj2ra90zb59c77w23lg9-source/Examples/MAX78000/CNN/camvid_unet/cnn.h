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

/*
 * This header file was automatically generated for the camvid_unet network from a template.
 * Please do not edit; instead, edit the template and regenerate.
 */

#ifndef __CNN_H__
#define __CNN_H__

#include <stdint.h>
typedef int32_t q31_t;
typedef int16_t q15_t;

/* Return codes */
#define CNN_FAIL 0
#define CNN_OK 1

/*
  SUMMARY OF OPS
  Hardware: 187,788,096 ops (186,753,024 macc; 1,035,072 comp; 0 add; 0 mul; 0 bitwise)
    Layer 0: 7,225,344 ops (7,077,888 macc; 147,456 comp; 0 add; 0 mul; 0 bitwise)
    Layer 1: 9,584,640 ops (9,437,184 macc; 147,456 comp; 0 add; 0 mul; 0 bitwise)
    Layer 2: 4,792,320 ops (4,718,592 macc; 73,728 comp; 0 add; 0 mul; 0 bitwise)
    Layer 3: 5,326,848 ops (5,308,416 macc; 18,432 comp; 0 add; 0 mul; 0 bitwise)
    Layer 4: 1,195,776 ops (1,161,216 macc; 34,560 comp; 0 add; 0 mul; 0 bitwise)
    Layer 5: 2,056,320 ops (2,032,128 macc; 24,192 comp; 0 add; 0 mul; 0 bitwise)
    Layer 6: 2,044,224 ops (2,032,128 macc; 12,096 comp; 0 add; 0 mul; 0 bitwise)
    Layer 7: 451,584 ops (451,584 macc; 0 comp; 0 add; 0 mul; 0 bitwise)
    Layer 8: 8,128,512 ops (8,128,512 macc; 0 comp; 0 add; 0 mul; 0 bitwise)
    Layer 9: 8,136,576 ops (8,128,512 macc; 8,064 comp; 0 add; 0 mul; 0 bitwise)
    Layer 10: 8,128,512 ops (8,128,512 macc; 0 comp; 0 add; 0 mul; 0 bitwise)
    Layer 11: 8,144,640 ops (8,128,512 macc; 16,128 comp; 0 add; 0 mul; 0 bitwise)
    Layer 12: 4,644,864 ops (4,644,864 macc; 0 comp; 0 add; 0 mul; 0 bitwise)
    Layer 13: 16,035,840 ops (15,925,248 macc; 110,592 comp; 0 add; 0 mul; 0 bitwise)
    Layer 14: 63,848,448 ops (63,700,992 macc; 147,456 comp; 0 add; 0 mul; 0 bitwise)
    Layer 15: 9,584,640 ops (9,437,184 macc; 147,456 comp; 0 add; 0 mul; 0 bitwise)
    Layer 16: 9,584,640 ops (9,437,184 macc; 147,456 comp; 0 add; 0 mul; 0 bitwise)
    Layer 17: 9,437,184 ops (9,437,184 macc; 0 comp; 0 add; 0 mul; 0 bitwise)
    Layer 18: 9,437,184 ops (9,437,184 macc; 0 comp; 0 add; 0 mul; 0 bitwise)

  RESOURCE USAGE
  Weight memory: 281,312 bytes out of 442,368 bytes total (64%)
  Bias memory:   908 bytes out of 2,048 bytes total (44%)
*/

/* Number of outputs for this network */
#define CNN_NUM_OUTPUTS 147456

/* Use this timer to time the inference */
#define CNN_INFERENCE_TIMER MXC_TMR0

/* Port pin actions used to signal that processing is active */

#define CNN_START LED_On(1)
#define CNN_COMPLETE LED_Off(1)
#define SYS_START LED_On(0)
#define SYS_COMPLETE LED_Off(0)

/* Run software SoftMax on unloaded data */
void softmax_q17p14_q15(const q31_t *vec_in, const uint16_t dim_vec, q15_t *p_out);
/* Shift the input, then calculate SoftMax */
void softmax_shift_q17p14_q15(q31_t *vec_in, const uint16_t dim_vec, uint8_t in_shift,
                              q15_t *p_out);

/* Stopwatch - holds the runtime when accelerator finishes */
extern volatile uint32_t cnn_time;

/* Custom memcopy routines used for weights and data */
void memcpy32(uint32_t *dst, const uint32_t *src, int n);
void memcpy32_const(uint32_t *dst, int n);

/* Enable clocks and power to accelerator, enable interrupt */
int cnn_enable(uint32_t clock_source, uint32_t clock_divider);

/* Disable clocks and power to accelerator */
int cnn_disable(void);

/* Perform minimum accelerator initialization so it can be configured */
int cnn_init(void);

/* Configure accelerator for the given network */
int cnn_configure(void);

/* Load accelerator weights */
int cnn_load_weights(void);

/* Verify accelerator weights (debug only) */
int cnn_verify_weights(void);

/* Load accelerator bias values (if needed) */
int cnn_load_bias(void);

/* Start accelerator processing */
int cnn_start(void);

/* Force stop accelerator */
int cnn_stop(void);

/* Continue accelerator after stop */
int cnn_continue(void);

/* Unload results from accelerator */
int cnn_unload(uint32_t *out_buf);

/* Turn on the boost circuit */
int cnn_boost_enable(mxc_gpio_regs_t *port, uint32_t pin);

/* Turn off the boost circuit */
int cnn_boost_disable(mxc_gpio_regs_t *port, uint32_t pin);

#endif // __CNN_H__
