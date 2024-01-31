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

#ifndef LIBRARIES_MAXUSB_INCLUDE_DEVCLASS_CDC_ACM_H_
#define LIBRARIES_MAXUSB_INCLUDE_DEVCLASS_CDC_ACM_H_

#include "usb_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file  cdc_acm.h
 * @brief Communications Device Class ACM (Serial Port) over USB.
 */

#ifdef MAXUSB_HS_CAPABLE
#define ACM_MAX_PACKET    MXC_USBHS_MAX_PACKET
#else
#define ACM_MAX_PACKET    64
#endif

#define ACM_PARITY_NONE   0
#define ACM_PARITY_ODD    1
#define ACM_PARITY_EVEN   2
#define ACM_PARITY_MARK   3
#define ACM_PARITY_SPACE  4

#define ACM_STOP_1        0
#define ACM_STOP_15       1
#define ACM_STOP_2        2

/// Configuration structure
typedef struct {
  uint8_t out_ep;            // endpoint to be used for OUT packets
  uint16_t out_maxpacket;    // max packet size for OUT endpoint
  uint8_t in_ep;             // endpoint to be used for IN packets
  uint16_t in_maxpacket;     // max packet size for IN endpoint
  uint8_t notify_ep;         // endpoint to be used for notifications
  uint16_t notify_maxpacket; // max packet size for notifications
} acm_cfg_t;

/// Line coding
#if defined(__GNUC__)
typedef struct __attribute__((packed)) {
#else
typedef __packed struct {
#endif
  uint32_t speed;   /// baud rate in bps
  uint8_t stopbits;
  uint8_t parity;
  uint8_t databits;
} acm_line_t;

/// CDC-ACM callback events
typedef enum {
  ACM_CB_CONNECTED,       /// upon host connection
  ACM_CB_DISCONNECTED,    /// upon host disconnection
  ACM_CB_SET_LINE_CODING, /// when new line coding parameters are received
  ACM_CB_READ_READY,      /// when new data is available from the host
  ACM_NUM_CALLBACKS       /// number of callback events for internal use
} acm_callback_t;

/**
 *  \brief    Initialize the class driver
 *  \details  Initialize the class driver.
 *  \param    if_desc  Pointer to the interface descriptor for the Comm Class
 *  \return   Zero (0) for success, non-zero for failure
 */
int acm_init(const MXC_USB_interface_descriptor_t *if_desc);

/**
 *  \brief    Set the specified configuration
 *  \details  Configures the class and endpoints and starts operation. This function should be
 *            called upon configuration from the host.
 *  \param    cfg   configuration to be set
 *  \return   Zero (0) for success, non-zero for failure
 */
int acm_configure(const acm_cfg_t *cfg);

/**
 *  \brief    Clear the current configuration and resets endpoints
 *  \details  Clear the current configuration and resets endpoints.
 *  \return   Zero (0) for success, non-zero for failure
 */
int acm_deconfigure(void);

/**
 *  \brief    Returns the current DTE status.
 *  \return   '1' if DTE is present, '0' otherwise
 */
int acm_present(void);

/**
 *  \brief    This function is used to get the current line coding
 *  \details  Upon an #ACM_CB_SET_LINE_CODING event, this function can be used to get the new
 *            line coding parameters.
 *  \return   pointer to the current line coding
 */
const acm_line_t *acm_line_coding(void);

/**
 *  \brief    Register a callback to be called upon the specified event.
 *  \details  Register a callback to be called upon the specified event. To disable the
 *            callback, call this function with a NULL parameter.
 *  \return   Zero (0) for success, non-zero for failure
 *  \note     Callbacks are executed in interrupt context
 */
int acm_register_callback(acm_callback_t cbnum, int (*func)(void));

/**
 *  \brief    Get the number of characters available to be read.
 *  \return   The number of characters available to be read.
 */
int acm_canread(void);

/**
 *  \brief    Read the specified number of characters.
 *  \details  Read the specified number of characters. This function blocks until the specified
 *            number of characters have been received.
 *  \param    buf   buffer to store the characters in
 *  \param    len   number of characters to read
 *  \return   Number of characters read, 0 if connection closes, -1 on error, or -2 if BREAK
 *            signal received.
 */
int acm_read(uint8_t *buf, unsigned int len);

/**
 *  \brief    Write the specified number of characters.
 *  \details  Write the specified number of characters. This function blocks until all characters
 *            have been transferred to and internal FIFO.
 *  \param    buf   buffer containing the characters to be sent
 *  \param    len   number of characters to write
 *  \return   The number of characters successfully written.
 *  \note     On some processors, the actually USB transaction is performed asynchronously, after
 *            this function returns. Successful return from this function does not guarantee
 *            successful reception of characters by the host.
 */
int acm_write(uint8_t *buf, unsigned int len);

#ifdef __cplusplus
}
#endif

#endif // LIBRARIES_MAXUSB_INCLUDE_DEVCLASS_CDC_ACM_H_
