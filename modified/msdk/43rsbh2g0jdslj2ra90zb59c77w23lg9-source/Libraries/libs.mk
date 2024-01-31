# This Makefile is used to manage the inclusion of the various
# libraries that are available in the MaximSDK.  'include'-ing 
# libs.mk offers 'toggle switch' variables that can be used to
# manage the inclusion of the available libraries.

# Each library below may also have its own set of configuration
# variables that can be overridden.

# If LIBS_DIR is not specified, this Makefile will locate itself.
LIBS_DIR ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# BSP (Enabled by default)
# ************************
LIB_BOARD ?= 1
ifeq ($(LIB_BOARD), 1)
BSP_SEARCH_DIR ?= $(LIBS_DIR)/Boards/$(TARGET_UC)
BOARD_DIR := $(BSP_SEARCH_DIR)/$(BOARD)
PROJ_CFLAGS += -DLIB_BOARD
include $(BOARD_DIR)/board.mk
endif
# ************************

# PeriphDrivers (Enabled by default)
# ************************
LIB_PERIPHDRIVERS ?= 1
ifeq ($(LIB_PERIPHDRIVERS), 1)
PERIPH_DRIVER_DIR := $(LIBS_DIR)/PeriphDrivers
include $(PERIPH_DRIVER_DIR)/periphdriver.mk
endif
# ************************

# CMSIS-DSP (Disabled by default)
# ************************
LIB_CMSIS_DSP ?= 0
ifeq ($(LIB_CMSIS_DSP), 1)
# Include the CMSIS-DSP library
include $(LIBS_DIR)/CMSIS/5.9.0/DSP/CMSIS-DSP.mk
endif
# ************************

# Cordio (Disabled by default)
# ************************
LIB_CORDIO ?= 0
ifeq ($(LIB_CORDIO), 1)
# Include the Cordio Library
CORDIO_DIR ?= $(LIBS_DIR)/Cordio
include $(CORDIO_DIR)/platform/targets/maxim/build/cordio_lib.mk

ifeq ($(RISCV_CORE),)
LIBS      += $(LIBS_DIR)/BlePhy/$(CHIP_UC)/libphy.a
else
LIBS      += $(LIBS_DIR)/BlePhy/$(CHIP_UC)/libphy_riscv.a
endif

endif
# ************************

# FCL (Disabled by default)
# ************************
LIB_FCL ?= 0
ifeq ($(LIB_FCL), 1)
FCL_DIR  ?= $(LIBS_DIR)/FCL
include $(FCL_DIR)/fcl.mk
endif
# ************************

# FreeRTOS (Disabled by default)
# ************************
LIB_FREERTOS ?= 0
ifeq ($(LIB_FREERTOS), 1)
# Where to find FreeRTOSConfig.h
RTOS_CONFIG_DIR ?= .

# Include FreeRTOS-Plus-CLI
IPATH += $(LIBS_DIR)/FreeRTOS-Plus/Source/FreeRTOS-Plus-CLI
VPATH += $(LIBS_DIR)/FreeRTOS-Plus/Source/FreeRTOS-Plus-CLI
SRCS += FreeRTOS_CLI.c

# Include the FreeRTOS library
include $(LIBS_DIR)/FreeRTOS/freertos.mk
endif
# ************************

# LC3 (Disabled by default)
# ************************
LIB_LC3 ?= 0
ifeq ($(LIB_LC3), 1)
LC3_ROOT ?= $(LIBS_DIR)/LC3
include $(LC3_ROOT)/build/sources.mk
endif
# ************************

# littleFS (Disabled by default)
# ************************
LIB_LITTLEFS ?= 0
ifeq ($(LIB_LITTLEFS), 1)
LITTLEFS_DIR ?= $(LIBS_DIR)/littlefs
include $(LITTLEFS_DIR)/littlefs.mk
endif
# ************************

# lvgl (Disabled by default)
# ************************
LIB_LVGL ?= 0
ifeq ($(LIB_LVGL), 1)
LVGL_DIR ?= $(LIBS_DIR)/LVGL
ENABLE_DISPLAY ?= 1
include $(LVGL_DIR)/lvgl.mk
endif
# ************************

# lwIP (Disabled by default)
# ************************
LIB_LWIP ?= 0
ifeq ($(LIB_LWIP), 1)
LWIP_DIR ?= $(LIBS_DIR)/lwIP
include $(LWIP_DIR)/lwip.mk
endif
# ************************

# MAXUSB (Disabled by default)
# ************************
LIB_MAXUSB ?= 0
ifeq ($(LIB_MAXUSB), 1)
MAXUSB_DIR ?= $(LIBS_DIR)/MAXUSB
include $(MAXUSB_DIR)/maxusb.mk
endif
# ************************

# SDHC (Disabled by default)
# ************************
LIB_SDHC ?= 0
ifeq ($(LIB_SDHC), 1)
# Set the SDHC driver directory
SDHC_DRIVER_DIR ?= $(LIBS_DIR)/SDHC

# Set the FAT32 driver directory
FAT32_DRIVER_DIR ?= $(SDHC_DRIVER_DIR)/ff13

# Include the SDHC library
include $(FAT32_DRIVER_DIR)/fat32.mk
include $(SDHC_DRIVER_DIR)/sdhc.mk
endif
# ************************

# NFC (Disabled by default)
# Only available via NDA
# ************************
LIB_NFC ?= 0
ifeq ($(LIB_NFC), 1)

# NFC lib has two components, pcd_pbm and rf_driver
LIB_NFC_PCD_PBM_DIR ?= $(LIBS_DIR)/NFC/lib_nfc_pcd_pbm
LIB_NFC_PCD_RF_DRIVER_DIR ?= $(LIBS_DIR)/NFC/lib_nfc_pcd_rf_driver_$(TARGET_UC)

ifeq ("$(wildcard $(LIB_NFC_PCD_PBM_DIR))","")
$(warning Warning: Failed to locate $(LIB_NFC_PCD_PBM_DIR))
$(error ERR_LIBNOTFOUND: NFC libraries not found (Only available via NDA).  Please install the NFC package to $(LIBS_DIR)/NFC)
endif

ifeq ("$(wildcard $(LIB_NFC_PCD_RF_DRIVER_DIR))","")
$(warning Warning: Failed to locate $(LIB_NFC_PCD_RF_DRIVER_DIR))
$(error ERR_LIBNOTFOUND: NFC libraries not found (Only available via NDA).  Please install the NFC package to $(LIBS_DIR)/NFC)
endif

ifneq ($(DEV_LIB_NFC),1)
# The libraries are released as pre-compiled library files.
# Only need to set up include paths and link library

# Add to include directory list
IPATH += $(LIB_NFC_PCD_PBM_DIR)/include
PROJ_LDFLAGS += -L$(LIB_NFC_PCD_PBM_DIR)
PROJ_LIBS += nfc_pcd_pbm_$(LIBRARY_VARIANT)

# Add to include directory list
IPATH += $(LIB_NFC_PCD_RF_DRIVER_DIR)/include
IPATH += $(LIB_NFC_PCD_RF_DRIVER_DIR)/include/nfc
PROJ_LDFLAGS += -L$(LIB_NFC_PCD_RF_DRIVER_DIR)
PROJ_LIBS += nfc_pcd_rf_driver_MAX32570_$(LIBRARY_VARIANT)

else
# Development setup (DEV_LIB_NFC=1) for building libraries
# from source
include $(LIB_NFC_PCD_PBM_DIR)/nfc_pcd_pbm.mk
include $(LIB_NFC_PCD_RF_DRIVER_DIR)/nfc_pcd_rf_driver.mk
endif

endif
# ************************

# EMV (Disabled by default)
# Only available via NDA
# ************************
LIB_EMV ?= 0
ifeq ($(LIB_EMV), 1)
EMV_DIR ?= $(LIBS_DIR)/EMV

ifeq ("$(wildcard $(EMV_DIR))","")
$(error ERR_LIBNOTFOUND: EMV library not found (Only available via NDA). Please install the EMV package to $(EMV_DIR))
endif

include $(EMV_DIR)/emv.mk
endif
# ************************

# UCL (Disabled by default)
# Only available via NDA
# ************************
LIB_UCL ?= 0
ifeq ($(LIB_UCL), 1)

UCL_DIR ?= $(LIBS_DIR)/UCL
ifeq ("$(wildcard $(UCL_DIR))","")
$(error ERR_LIBNOTFOUND: UCL not found (Only available via NDA). Please install the UCL package to $(UCL_DIR))
endif

include $(UCL_DIR)/ucl.mk

endif
# ************************

# Barcode Decoder (Disabled by default)
# ************************
LIB_BARCODE_DECODER ?= 0
ifeq ($(LIB_BARCODE_DECODER), 1)
BARCODE_DECODER_DIR ?= $(LIBS_DIR)/MiscDrivers/BarcodeDecoder/zbar
include $(BARCODE_DECODER_DIR)/barcode_decoder.mk
endif
# ************************
