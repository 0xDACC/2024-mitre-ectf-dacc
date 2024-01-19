# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://github.com/Analog-Devices-MSDK/VSCode-Maxim/tree/develop#build-configuration

# **********************************************************

# Enable CORDIO library
LIB_CORDIO = 1

# Enable the FreeRTOS library
LIB_FREERTOS=1

# Enable Cordio use of FreeRTOS
RTOS = freertos

# Optimize for size
MXC_OPTIMIZE_CFLAGS = -Os

# Enable low level trace
TRACE = 2