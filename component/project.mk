# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

#MXC_OPTIMIZE_CFLAGS = -Os
# ^ For example, you can uncomment this line to 
# optimize the project for debugging

# **********************************************************

# Add your config here!

# This example is only compatible with the FTHR board,
# so we override the BOARD value to hard-set it.
override BOARD=FTHR_RevA
MFLOAT_ABI=soft

IPATH+=../deployment
IPATH+=inc/
IPATH+=../lib/tinycrypt/include
VPATH+=src/
VPATH+=../lib/tinycrypt/src

#PROJ_CFLAGS+=-Wall -Wextra -s -fomit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-math-errno -fno-ident -ffast-math -nostdlib -nostdinc++
#PROJ_CFLAGS+=-Wall -s -fomit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-math-errno -fno-ident -ffast-math -nostdlib -nostdinc++
# ****************** eCTF Bootloader *******************
# DO NOT REMOVE
LINKERFILE=firmware.ld
STARTUPFILE=startup_firmware.S
ENTRY=firmware_startup

# ****************** eCTF Crypto Example *******************
# Uncomment the commented lines below and comment the disable
# lines to enable the eCTF Crypto Example.
# WolfSSL must be included in this directory as wolfssl/
# WolfSSL can be downloaded from: https://www.wolfssl.com/download/
# There is no additional functionality as in the application_processor
# but this will set up compilation and linking for WolfSSL

# Disable Crypto Example
CRYPTO_EXAMPLE=0

# Enable Crypto Example
#CRYPTO_EXAMPLE=1

secrets:
	python make_secret.py