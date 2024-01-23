################################################################################
 # Copyright (C) 2023 Maxim Integrated Products, Inc., All Rights Reserved.
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

################################################################################
# This file can be included in a project makefile to build the library for the 
# project.
################################################################################

ifeq "$(SDHC_DRIVER_DIR)" ""
$(error SDHC_DRIVER_DIR must be specified")
endif

# Specify the build directory if not defined by the project
ifeq "$(BUILD_DIR)" ""
SDHC_DRIVER_BUILD_DIR=$(CURDIR)/build/SDHCDriver
else
SDHC_DRIVER_BUILD_DIR=$(BUILD_DIR)/SDHCDriver
endif

# Export paths needed by the SDHC driver makefile. Since the makefile to
# build the library will execute in a different directory, paths must be
# specified absolutely
SDHC_DRIVER_BUILD_DIR := ${abspath ${SDHC_DRIVER_BUILD_DIR}}
export TOOL_DIR := ${abspath ${TOOL_DIR}}
export CMSIS_ROOT := ${abspath ${CMSIS_ROOT}}
export PERIPH_DRIVER_DIR := ${abspath ${PERIPH_DRIVER_DIR}}
export MISC_DRIVERS_DIR=$(LIBS_DIR)/MiscDrivers

# Export other variables needed by the peripheral driver makefile
export TARGET
export COMPILER
export TARGET_MAKEFILE
export PROJ_CFLAGS
export PROJ_LDFLAGS
export MXC_OPTIMIZE_CFLAGS
export BOARD_DIR
export USE_NATIVE_SDHC
export EXTERNAL_FLASH
# Add to library list
LIBS += ${SDHC_DRIVER_BUILD_DIR}/sdhc.a

# Add to include directory list
IPATH += ${SDHC_DRIVER_DIR}/Include

# Add rule to build the Driver Library
${SDHC_DRIVER_BUILD_DIR}/sdhc.a: FORCE
	$(MAKE) -C ${SDHC_DRIVER_DIR} lib BUILD_DIR=${SDHC_DRIVER_BUILD_DIR} BOARD=${BOARD}

