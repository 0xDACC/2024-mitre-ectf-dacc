################################################################################
 # Copyright (C) Maxim Integrated Products, Inc., All Rights Reserved.
 #
 # Permission is hereby granted, free of charge, to any person obtaining a
 # copy of this software and associated documentation files (the "Software"),
 # to deal in the Software without restriction, including without limitation
 # the rights to use, copy, modify, merge, publish, distribute, sublicense,
 # and/or sell copies of the Software, and to permit persons to whom the
 # Software is furnished to do so, subject to the following conditions:
 #
 # The above copyright notice and this permission notice shall be included
 # in all copies or substantial portions of the Software.
 #
 # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 # IN NO EVENT SHALL MAXIM INTEGRATED BE LIABLE FOR ANY CLAIM, DAMAGES
 # OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 # ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 # OTHER DEALINGS IN THE SOFTWARE.
 #
 # Except as contained in this notice, the name of Maxim Integrated
 # Products, Inc. shall not be used except as stated in the Maxim Integrated
 # Products, Inc. Branding Policy.
 #
 # The mere transfer of this software does not imply any licenses
 # of trade secrets, proprietary technology, copyrights, patents,
 # trademarks, maskwork rights, or any other form of intellectual
 # property whatsoever. Maxim Integrated Products, Inc. retains all
 # ownership rights.
 #
 ###############################################################################

ifeq "$(BOARD_DIR)" ""
$(error BOARD_DIR must be set)
endif

# Source files for this test (add path to VPATH below)
SRCS += board.c
SRCS += stdio.c
SRCS += led.c
SRCS += camera.c
ifeq "$(CAMERA)" "HM0360_MONO"
SRCS += hm0360_mono.c
SRCS += debayering.c
PROJ_CFLAGS+=-DCAMERA_HM0360_MONO
PROJ_CFLAGS+=-DCAMERA_MONO
else ifeq "$(CAMERA)" "HM0360_COLOR"
SRCS += hm0360_color.c
SRCS += debayering.c
PROJ_CFLAGS+=-DCAMERA_BAYER
PROJ_CFLAGS+=-DCAMERA_HM0360_COLOR
endif
SRCS += sccb.c

MISC_DRIVERS_DIR=$(BOARD_DIR)/../../../MiscDrivers

# Where to find BSP source files
VPATH += $(BOARD_DIR)/Source
VPATH += $(BOARD_DIR)/../Source # Add core BSP source directory
VPATH += $(MISC_DRIVERS_DIR)
VPATH += $(MISC_DRIVERS_DIR)/Camera
VPATH += $(MISC_DRIVERS_DIR)/Display
VPATH += $(MISC_DRIVERS_DIR)/LED
VPATH += $(MISC_DRIVERS_DIR)/PushButton
VPATH += $(MISC_DRIVERS_DIR)/Touchscreen


# Where to find BSP header files
IPATH += $(BOARD_DIR)/Include
IPATH += $(BOARD_DIR)/../Include # Add core BSP include directory
IPATH += $(MISC_DRIVERS_DIR)
IPATH += $(MISC_DRIVERS_DIR)/Camera
IPATH += $(MISC_DRIVERS_DIR)/Display
IPATH += $(MISC_DRIVERS_DIR)/LED
IPATH += $(MISC_DRIVERS_DIR)/PushButton
IPATH += $(MISC_DRIVERS_DIR)/Touchscreen
