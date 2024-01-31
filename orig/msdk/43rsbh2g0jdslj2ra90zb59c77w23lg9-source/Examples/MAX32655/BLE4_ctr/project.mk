# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

# **********************************************************

# Enable Cordio library
LIB_CORDIO = 1

# Cordio library options
BLE_HOST = 0
BLE_CONTROLLER = 1
BT_VER = 8

# TRACE option
# Set to 0 to disable
# Set to 2 to enable serial port trace messages
TRACE = 2
