# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

# **********************************************************

# Add your config here!

# If you have secure version of MCU, set SBT=1 to generate signed binary
# For more information on how sing process works, see
# https://www.analog.com/en/education/education-library/videos/6313214207112.html
SBT=0

# Enable LVGL library
LIB_LVGL = 1

VPATH += resources

ifneq ($(BOARD),EvKit_V1)
$(error ERR_NOTSUPPORTED: This example requires a TFT display, therefore it's only supported by the MAX32665EVKIT)
endif

