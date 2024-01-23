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
 * @brief   USB Mass Storage Class example
 * @details This project creates a mass storage device using either on-board RAM or
 *          external SPI flash memory.  Load the project, connect a cable from the PC
 *          to the USB connector.  A new external drive should appear than can be read
 *          and written.
 */

#include <stdio.h>
#include <stddef.h>

#include <MAX32xxx.h>

#include "usb.h"
#include "usb_event.h"
#include "usb_protocol.h"
#include "enumerate.h"
#include "msc.h"
#include "descriptors.h"
#include "mscmem.h"

/***** Definitions *****/
#define EVENT_ENUM_COMP MAXUSB_NUM_EVENTS
#define EVENT_REMOTE_WAKE (EVENT_ENUM_COMP + 1)

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

/***** Global Data *****/
int remoteWake;
volatile int configured;
volatile int suspended;
volatile unsigned int evtFlags;

/***** Function Prototypes *****/
int usbStartupCallback();
int usbShutdownCallback();
void usDelay(unsigned int usec);
static void usbAppSleep(void);
static void usbAppWakeup(void);
static int setconfigCallback(MXC_USB_SetupPkt *sud, void *cbdata);
static int setfeatureCallback(MXC_USB_SetupPkt *sud, void *cbdata);
static int clrfeatureCallback(MXC_USB_SetupPkt *sud, void *cbdata);
static int eventCallback(maxusb_event_t evt, void *data);

/***** File Scope Variables *****/

/* This EP assignment must match the Configuration Descriptor */
static const msc_cfg_t msc_cfg = {
    1, /* EP OUT */
    MXC_USBHS_MAX_PACKET, /* OUT max packet size */
    2, /* EP IN */
    MXC_USBHS_MAX_PACKET, /* IN max packet size */
};

static const msc_idstrings_t ids = {
    "MAXIM", /* Vendor string.  Maximum of 8 bytes */
    "MSC Example", /* Product string.  Maximum of 16 bytes */
    "1.0" /* Version string.  Maximum of 4 bytes */
};

/* Functions to control "disk" memory. See msc.h for definitions. */
static const msc_mem_t mem = {
    mscmem_Init, mscmem_Start, mscmem_Stop, mscmem_Ready, mscmem_Size, mscmem_Read, mscmem_Write,
};

/******************************************************************************/
void SysTick_Handler(void)
{
    MXC_DelayHandler();
}

/******************************************************************************/
void USB_IRQHandler(void)
{
    MXC_USB_EventHandler();
}

/******************************************************************************/
int main(void)
{
    maxusb_cfg_options_t usb_opts;

    printf("\n\n***** " TOSTRING(TARGET) " USB Mass Storage Example *****\n");
    printf("Waiting for VBUS...\n");

    /* Initialize state */
    configured = 0;
    suspended = 0;
    evtFlags = 0;
    remoteWake = 0;

    /* Start out in full speed */
    usb_opts.enable_hs = 0;
    usb_opts.delay_us = usDelay; /* Function which will be used for delays */
    usb_opts.init_callback = usbStartupCallback;
    usb_opts.shutdown_callback = usbShutdownCallback;

    /* Initialize the usb module */
    if (MXC_USB_Init(&usb_opts) != 0) {
        printf("MXC_USB_Init() failed\n");

        while (1) {}
    }

    /* Initialize the enumeration module */
    if (enum_init() != 0) {
        printf("enum_init() failed\n");

        while (1) {}
    }

    /* Register enumeration data */
    enum_register_descriptor(ENUM_DESC_DEVICE, (uint8_t *)&device_descriptor, 0);
    enum_register_descriptor(ENUM_DESC_CONFIG, (uint8_t *)&config_descriptor, 0);
    enum_register_descriptor(ENUM_DESC_STRING, lang_id_desc, 0);
    enum_register_descriptor(ENUM_DESC_STRING, mfg_id_desc, 1);
    enum_register_descriptor(ENUM_DESC_STRING, prod_id_desc, 2);
    enum_register_descriptor(ENUM_DESC_STRING, serial_id_desc, 3);

    /* Handle configuration */
    enum_register_callback(ENUM_SETCONFIG, setconfigCallback, NULL);

    /* Handle feature set/clear */
    enum_register_callback(ENUM_SETFEATURE, setfeatureCallback, NULL);
    enum_register_callback(ENUM_CLRFEATURE, clrfeatureCallback, NULL);

    /* Initialize the class driver */
    if (msc_init(&config_descriptor.msc_interface_descriptor, &ids, &mem) != 0) {
        printf("msc_init() failed\n");

        while (1) {}
    }

    /* Register callback */
    MXC_USB_EventEnable(MAXUSB_EVENT_NOVBUS, eventCallback, NULL);
    MXC_USB_EventEnable(MAXUSB_EVENT_VBUS, eventCallback, NULL);

    /* Start with USB in low power mode */
    usbAppSleep();
    NVIC_EnableIRQ(USB_IRQn);

    /* Wait for events */
    while (1) {
        if (suspended || !configured) {
            LED_Off(0);
        } else {
            LED_On(0);
        }

        if (evtFlags) {
            /* Display events */
            if (MXC_GETBIT(&evtFlags, MAXUSB_EVENT_NOVBUS)) {
                MXC_CLRBIT(&evtFlags, MAXUSB_EVENT_NOVBUS);
                printf("VBUS Disconnect\n");
            } else if (MXC_GETBIT(&evtFlags, MAXUSB_EVENT_VBUS)) {
                MXC_CLRBIT(&evtFlags, MAXUSB_EVENT_VBUS);
                printf("VBUS Connect\n");
            } else if (MXC_GETBIT(&evtFlags, MAXUSB_EVENT_BRST)) {
                MXC_CLRBIT(&evtFlags, MAXUSB_EVENT_BRST);
                printf("Bus Reset\n");
            } else if (MXC_GETBIT(&evtFlags, MAXUSB_EVENT_SUSP)) {
                MXC_CLRBIT(&evtFlags, MAXUSB_EVENT_SUSP);
                printf("Suspended\n");
            } else if (MXC_GETBIT(&evtFlags, MAXUSB_EVENT_DPACT)) {
                MXC_CLRBIT(&evtFlags, MAXUSB_EVENT_DPACT);
                printf("Resume\n");
            } else if (MXC_GETBIT(&evtFlags, EVENT_ENUM_COMP)) {
                MXC_CLRBIT(&evtFlags, EVENT_ENUM_COMP);
                printf("Enumeration complete.\n");
            } else if (MXC_GETBIT(&evtFlags, EVENT_REMOTE_WAKE)) {
                MXC_CLRBIT(&evtFlags, EVENT_REMOTE_WAKE);
                printf("Remote Wakeup\n");
            }
        }
    }
}

/* This callback is used to allow the driver to call part specific initialization functions. */
/******************************************************************************/
int usbStartupCallback()
{
    // Startup the HIRC96M clock if it's not on already
    if (!(MXC_GCR->clkctrl & MXC_F_GCR_CLKCTRL_IPO_EN)) {
        MXC_GCR->clkctrl |= MXC_F_GCR_CLKCTRL_IPO_EN;

        if (MXC_SYS_Clock_Timeout(MXC_F_GCR_CLKCTRL_IPO_RDY) != E_NO_ERROR) {
            return E_TIME_OUT;
        }
    }

    MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_USB);

    return E_NO_ERROR;
}

/******************************************************************************/
int usbShutdownCallback()
{
    MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_USB);

    return E_NO_ERROR;
}

/* User-supplied function to delay usec micro-seconds */
/******************************************************************************/
void usDelay(unsigned int usec)
{
    /* mxc_delay() takes unsigned long, so can't use it directly */
    MXC_Delay(usec);
}

/******************************************************************************/
static void usbAppSleep(void)
{
    /* TODO: Place low-power code here */
    suspended = 1;
}

/******************************************************************************/
static void usbAppWakeup(void)
{
    /* TODO: Place low-power code here */
    suspended = 0;
}

/******************************************************************************/
static int setconfigCallback(MXC_USB_SetupPkt *sud, void *cbdata)
{
    /* Confirm the configuration value */
    if (sud->wValue == config_descriptor.config_descriptor.bConfigurationValue) {
        configured = 1;
        MXC_SETBIT(&evtFlags, EVENT_ENUM_COMP);
        return msc_configure(&msc_cfg, config_descriptor.msc_interface_descriptor
                                           .bInterfaceNumber); /* Configure the device class */
    } else if (sud->wValue == 0) {
        configured = 0;
        return msc_deconfigure(config_descriptor.msc_interface_descriptor.bInterfaceNumber);
    }

    return -1;
}

/******************************************************************************/
static int setfeatureCallback(MXC_USB_SetupPkt *sud, void *cbdata)
{
    if (sud->wValue == FEAT_REMOTE_WAKE) {
        remoteWake = 1;
    } else {
        // Unknown callback
        return -1;
    }

    return 0;
}

/******************************************************************************/
static int clrfeatureCallback(MXC_USB_SetupPkt *sud, void *cbdata)
{
    if (sud->wValue == FEAT_REMOTE_WAKE) {
        remoteWake = 0;
    } else {
        // Unknown callback
        return -1;
    }

    return 0;
}

/******************************************************************************/
static int eventCallback(maxusb_event_t evt, void *data)
{
    /* Set event flag */
    MXC_SETBIT(&evtFlags, evt);

    switch (evt) {
    case MAXUSB_EVENT_NOVBUS:
        MXC_USB_EventDisable(MAXUSB_EVENT_BRST);
        MXC_USB_EventDisable(MAXUSB_EVENT_SUSP);
        MXC_USB_EventDisable(MAXUSB_EVENT_DPACT);
        MXC_USB_Disconnect();
        configured = 0;
        enum_clearconfig();
        msc_deconfigure(config_descriptor.msc_interface_descriptor.bInterfaceNumber);
        usbAppSleep();
        break;

    case MAXUSB_EVENT_VBUS:
        MXC_USB_EventClear(MAXUSB_EVENT_BRST);
        MXC_USB_EventEnable(MAXUSB_EVENT_BRST, eventCallback, NULL);
        MXC_USB_EventClear(MAXUSB_EVENT_SUSP);
        MXC_USB_EventEnable(MAXUSB_EVENT_SUSP, eventCallback, NULL);
        MXC_USB_Connect();
        usbAppSleep();
        break;

    case MAXUSB_EVENT_BRST:
        usbAppWakeup();
        enum_clearconfig();
        msc_deconfigure(config_descriptor.msc_interface_descriptor.bInterfaceNumber);
        configured = 0;
        suspended = 0;
        break;

    case MAXUSB_EVENT_SUSP:
        usbAppSleep();
        break;

    case MAXUSB_EVENT_DPACT:
        usbAppWakeup();
        break;

    default:
        break;
    }

    return 0;
}
