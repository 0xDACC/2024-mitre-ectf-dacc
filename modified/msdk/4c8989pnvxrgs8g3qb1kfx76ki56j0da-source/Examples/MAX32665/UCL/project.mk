# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

# **********************************************************

# Enable UCL library
LIB_UCL = 1
export UCL_VERSION=2.7.0

MFLOAT_ABI=hard
MFPU_FLAGS=fpv4-sp-d16

# Add project's include and source paths
VPATH += ./src
VPATH += ./src/cipher
VPATH += ./src/public_key
VPATH += ./src/mac

IPATH += ./src/include

# Set variant part number
TARGET_SEC="MAX32666"

# MAX32666 is secure micro so that enable SBT
SBT = 1
