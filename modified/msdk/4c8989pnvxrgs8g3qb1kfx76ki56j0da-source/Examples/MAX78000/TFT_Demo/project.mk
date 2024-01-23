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

IPATH += resources

# Place build files specific to EvKit_V1 here.
ifeq "$(BOARD)" "EvKit_V1"
VPATH += resources/tft_evkit
endif

# Place build files specific to FTHR_RevA here.
ifeq "$(BOARD)" "FTHR_RevA"
VPATH += resources/tft_fthr
endif


ifeq ($(BOARD),Aud01_RevA)
$(error ERR_NOTSUPPORTED: This project is not supported for the Audio board)
endif

ifeq ($(BOARD),CAM01_RevA)
$(error ERR_NOTSUPPORTED: This project is not supported for the CAM01 board)
endif

