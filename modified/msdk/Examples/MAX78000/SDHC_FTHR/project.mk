# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

#MXC_OPTIMIZE_CFLAGS = -Og
# ^ For example, you can uncomment this line to 
# optimize the project for debugging

# **********************************************************

# Add your config here!

BOARD = FTHR_RevA

ifneq ($(BOARD),FTHR_RevA)
$(error ERR_NOTSUPPORTED: This project requires an SD card slot and is only supported for the MAX78000FTHR)
endif

LIB_SDHC = 1

