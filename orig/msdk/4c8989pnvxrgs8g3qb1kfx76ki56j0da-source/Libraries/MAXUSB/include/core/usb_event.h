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
 * Low-layer API calls
 *
 * These do not change, and provide the basis by which usb.c acceses the 
 *  hardware. All usbio.c drivers will provide these calls, or return an
 *  error if the function is not supported.
 * 
 */

#ifndef LIBRARIES_MAXUSB_INCLUDE_CORE_USB_EVENT_H_
#define LIBRARIES_MAXUSB_INCLUDE_CORE_USB_EVENT_H_

#include "usb.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file MXC_USB_event.h
 * @brief Defines the API used for USB event handling
 *
 */

/***** Definitions *****/
typedef struct {
  int (*func)(maxusb_event_t, void *);
  void *cbdata;
} MXC_USB_event_callback_t;

/** 
 * @brief Register a callback for and enable the specified event
 * @param event   event number
 * @param func    function to be called
 * @param cbdata  parameter to call callback function with
 * @return This function returns zero (0) for success, non-zero for failure
 */
int MXC_USB_EventEnable(maxusb_event_t event, int (*callback)(maxusb_event_t, void *), void *cbdata);

/** 
 * @brief Enable the specified event
 * @param event   event number
 * @return This function returns zero (0) for success, non-zero for failure
 */
int MXC_USB_EventDisable(maxusb_event_t event);

/** 
 * @brief Clear the specified event
 * @param event   event number
 * @return This function returns zero (0) for success, non-zero for failure
 */
int MXC_USB_EventClear(maxusb_event_t event);

/** 
 * @brief Processes USB events
 * This function should be called from the USB interrupt vector or periodically
 * from the application.
 */
void MXC_USB_EventHandler(void);

#ifdef __cplusplus
}
#endif

#endif //LIBRARIES_MAXUSB_INCLUDE_CORE_USB_EVENT_H_
