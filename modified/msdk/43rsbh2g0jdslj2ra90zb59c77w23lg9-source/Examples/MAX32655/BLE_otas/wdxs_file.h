/*************************************************************************************************/
/*!
 *  \file
 *
 *  \brief  Wireless Data Exchange profile implementation - File Example.
 *
 *  Copyright (c) 2013-2018 Arm Ltd. All Rights Reserved.
 *  ARM Ltd. confidential and proprietary.
 *
 *  IMPORTANT.  Your use of this file is governed by a Software License Agreement
 *  ("Agreement") that must be accepted in order to download or otherwise receive a
 *  copy of this file.  You may not use or copy this file for any purpose other than
 *  as described in the Agreement.  If you do not agree to all of the terms of the
 *  Agreement do not use this file and delete all copies in your possession or control;
 *  if you do not have a copy of the Agreement, you must contact ARM Ltd. prior
 *  to any use, copying or further distribution of this software.
 */
/*************************************************************************************************/

#ifndef EXAMPLES_MAX32655_BLE_OTAS_WDXS_FILE_H_
#define EXAMPLES_MAX32655_BLE_OTAS_WDXS_FILE_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t fileLen;
    uint32_t fileCRC;
} fileHeader_t;

/*! \addtogroup WIRELESS_DATA_EXCHANGE_PROFILE
 *  \{ */

/**************************************************************************************************
  Constant Definitions
**************************************************************************************************/

/**************************************************************************************************
  Function Declarations
**************************************************************************************************/

/*************************************************************************************************/
/*!
 *  \brief  Initialize the WDXS File.
 *
 *  \return None.
 */
/*************************************************************************************************/
void WdxsFileInit(void);

/*************************************************************************************************/
/*!
 *  \brief  Get the base address of the WDXS file.
 *
 *  \return Base address of WDXS file.
 */
/*************************************************************************************************/
uint32_t WdxsFileGetBaseAddr(void);

/*************************************************************************************************/
/*!
 *  \brief  Get the length of the last verified WDXS file.
 *
 *  \return Verified length of WDXS file.
 */
/*************************************************************************************************/
uint32_t WdxsFileGetVerifiedLength(void);

/*************************************************************************************************/
/*!
 *  \brief  Get the firmware version of the WDXS file.
 *
 *  \return Firmware version of the WDXS file.
 */
/*************************************************************************************************/
uint16_t WdxsFileGetFirmwareVersion(void);
/*************************************************************************************************/
/*!
 *  \brief  set the length of the expected file
 *
 *  \return None.
 */
/*************************************************************************************************/
void initHeader(fileHeader_t *header);
/*! \} */ /* WIRELESS_DATA_EXCHANGE_PROFILE */

#ifdef __cplusplus
}
#endif

#endif // EXAMPLES_MAX32655_BLE_OTAS_WDXS_FILE_H_
