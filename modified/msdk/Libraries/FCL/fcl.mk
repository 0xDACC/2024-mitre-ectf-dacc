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
 
ifeq "$(FCL_DIR)" ""
$(error FCL_DIR must be specified")
endif

TARGET_UC:=$(shell echo $(TARGET) | tr a-z A-Z)
TARGET_LC:=$(shell echo $(TARGET) | tr A-Z a-z)

# Specify the library variant.
ifeq "$(MFLOAT_ABI)" "hardfp"
LIBRARY_VARIANT=hardfp
else
ifeq "$(MFLOAT_ABI)" "hard"
LIBRARY_VARIANT=hardfp
else
LIBRARY_VARIANT=softfp
endif
endif

# Specify the build directory if not defined by the project
ifeq "$(BUILD_DIR)" ""
FCL_BUILD_DIR=${FCL_DIR}/bin/$(LIBRARY_VARIANT)
else
FCL_BUILD_DIR=$(BUILD_DIR)/FCL
endif

# Export other variables needed by the peripheral driver makefile
export TARGET
export COMPILER
export TARGET_MAKEFILE
export PROJ_CFLAGS
export PROJ_LDFLAGS
export MXC_OPTIMIZE_CFLAGS

include ${FCL_DIR}/fcl_files.mk
IPATH += ${FCL_INCLUDE_DIR}
ifeq "$(LIBRARY_VARIANT)" ""
FCL_LIB := libfcl.a
else
FCL_LIB := libfcl_$(LIBRARY_VARIANT).a
endif

# export FCL_DIR
export FCL_LIB
export FCL_BUILD_DIR

# Add to library list
LIBS += ${FCL_BUILD_DIR}/${FCL_LIB}
# Add rule to build the Driver Library
${FCL_BUILD_DIR}/${FCL_LIB}: ${FCL_C_FILES} ${FCL_H_FILES}
	$(MAKE) -f ${FCL_DIR}/libfcl.mk  lib BUILD_DIR=${FCL_BUILD_DIR} 

clean.fcl:
	@rm -rf ${FCL_BUILD_DIR}/*