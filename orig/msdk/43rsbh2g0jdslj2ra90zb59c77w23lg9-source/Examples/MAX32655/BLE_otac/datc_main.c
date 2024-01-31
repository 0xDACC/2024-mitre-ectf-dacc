/*************************************************************************************************/
/*!
 *  \file
 *
 *  \brief  Proprietary data transfer client sample application for Nordic-ble.
 *
 *  Copyright (c) 2012-2019 Arm Ltd. All Rights Reserved.
 *
 *  Copyright (c) 2019-2020 Packetcraft, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
/*************************************************************************************************/

#include <string.h>
#include <stdlib.h>
#include "wsf_types.h"
#include "util/bstream.h"
#include "wsf_msg.h"
#include "wsf_trace.h"
#include "wsf_assert.h"
#include "wsf_buf.h"
#include "wsf_nvm.h"
#include "hci_api.h"
#include "dm_api.h"
#include "dm_priv.h"
#include "gap/gap_api.h"
#include "att_api.h"
#include "smp_api.h"
#include "app_cfg.h"
#include "app_api.h"
#include "app_db.h"
#include "app_ui.h"
#include "svc_core.h"
#include "svc_ch.h"
#include "gatt/gatt_api.h"
#include "wpc/wpc_api.h"
#include "datc_api.h"
#include "util/calc128.h"
#include "wsf_efs.h"
#include "wdxc/wdxc_api.h"
#include "wdxc/wdxc_main.h"
#include "wdx_defs.h"
#include "pal_btn.h"
#include "tmr.h"

/**************************************************************************************************
Macros
**************************************************************************************************/
#if (BT_VER > 8)
/* PHY Test Modes */
#define DATC_PHY_1M 1
#define DATC_PHY_2M 2
#define DATC_PHY_CODED 3
#endif /* BT_VER */

/* Size of WDXC file discovery dataset */
#define DATC_WDXC_MAX_FILES 4

/*! WSF message event starting value */
#define DATC_MSG_START 0xA0

/*! Data rate timer period in seconds */
#define DATC_WDXS_DATA_RATE_TIMEOUT 4

extern uint32_t _binary_fw_update_bin_start;
extern uint32_t _binary_fw_update_bin_end;

#define FILE_SIZE \
    (uint32_t)(((uint32_t)&_binary_fw_update_bin_end) - ((uint32_t)&_binary_fw_update_bin_start))
#define BLOCK_OFFSET_INIT 0x0
#define BLOCK_SIZE 224
#define CRC32_LEN 4

/*! Button press handling constants */
#define BTN_SHORT_MS 200
#define BTN_MED_MS 500
#define BTN_LONG_MS 1000

#define BTN_1_TMR MXC_TMR2
#define BTN_2_TMR MXC_TMR3

#define SCAN_START_EVT 0x99
#define SCAN_START_MS 500

/**************************************************************************************************
  Local Variables
**************************************************************************************************/
typedef struct {
    uint32_t fileLen;
    uint32_t fileCRC;
} fileHeader_t;
fileHeader_t fileHeader;
/*! application control block */
struct {
    uint16_t hdlList[DM_CONN_MAX][APP_DB_HDL_LIST_LEN]; /*! Cached handle list */
    wsfHandlerId_t handlerId; /*! WSF hander ID */
    bool_t scanning; /*! TRUE if scanning */
    bool_t autoConnect; /*! TRUE if auto-connecting */
    uint8_t discState[DM_CONN_MAX]; /*! Service discovery state */
    uint8_t hdlListLen; /*! Cached handle list length */
    uint8_t btnConnId; /*! The index of the connection ID for button presses */
    bool_t sendingFile[DM_CONN_MAX];
    bool_t fileVerified[DM_CONN_MAX];
    uint32_t blockOffset[DM_CONN_MAX];
    wsfEfsFileInfo_t fileList[DM_CONN_MAX][DATC_WDXC_MAX_FILES]; /*! Buffer to hold WDXC file list */
    uint8_t *fileData; /*! Pointer for accessing the fw_update image*/
    uint32_t fileCRC; /*! Holds the CRC32 value of the file */
    uint32_t blockSize;

    appDbHdl_t resListRestoreHdl; /*! Resolving List restoration handle */
    bool_t restoringResList; /*! Restoring resolving list from NVM */
    wsfTimer_t scanTimer; /* Timer for starting the scanner */
} datcCb;

/*! connection control block */
typedef struct {
    appDbHdl_t dbHdl; /*! Device database record handle type */
    uint8_t addrType; /*! Type of address of device to connect to */
    bdAddr_t addr; /*! Address of device to connect to */
    bool_t doConnect; /*! TRUE to issue connect on scan complete */
} datcConnInfo_t;

datcConnInfo_t datcConnInfo;

/**************************************************************************************************
  Configurable Parameters
**************************************************************************************************/

/*! configurable parameters for master */
static const appMasterCfg_t datcMasterCfg = {
    96, /*! The scan interval, in 0.625 ms units */
    48, /*! The scan window, in 0.625 ms units  */
    0, /*! The scan duration in ms */
    DM_DISC_MODE_NONE, /*! The GAP discovery mode */
    DM_SCAN_TYPE_ACTIVE /*! The scan type (active or passive) */
};

/*! configurable parameters for security */
static const appSecCfg_t datcSecCfg = {
    DM_AUTH_BOND_FLAG | DM_AUTH_SC_FLAG, /*! Authentication and bonding flags */
    DM_KEY_DIST_IRK, /*! Initiator key distribution flags */
    DM_KEY_DIST_LTK | DM_KEY_DIST_IRK, /*! Responder key distribution flags */
    FALSE, /*! TRUE if Out-of-band pairing data is present */
    TRUE /*! TRUE to initiate security upon connection */
};

/*! TRUE if Out-of-band pairing data is to be sent */
static const bool_t datcSendOobData = FALSE;

/*! SMP security parameter configuration */
static const smpCfg_t datcSmpCfg = {
    500, /*! 'Repeated attempts' timeout in msec */
    SMP_IO_NO_IN_NO_OUT, /*! I/O Capability */
    7, /*! Minimum encryption key length */
    16, /*! Maximum encryption key length */
    1, /*! Attempts to trigger 'repeated attempts' timeout */
    0, /*! Device authentication requirements */
    64000, /*! Maximum repeated attempts timeout in msec */
    64000, /*! Time msec before attemptExp decreases */
    2 /*! Repeated attempts multiplier exponent */
};

/*! Connection parameters */
static const hciConnSpec_t datcConnCfg = {
    6, /*! Minimum connection interval in 1.25ms units */
    6, /*! Maximum connection interval in 1.25ms units */
    0, /*! Connection latency */
    600, /*! Supervision timeout in 10ms units */
    0, /*! Unused */
    0 /*! Unused */
};

/*! Configurable parameters for service and characteristic discovery */
static const appDiscCfg_t datcDiscCfg = {
    FALSE, /*! TRUE to wait for a secure connection before initiating discovery */
    TRUE /*! TRUE to fall back on database hash to verify handles when no bond exists. */
};

static const appCfg_t datcAppCfg = {
    FALSE, /*! TRUE to abort service discovery if service not found */
    TRUE /*! TRUE to disconnect if ATT transaction times out */
};

/*! ATT configurable parameters (increase MTU) */
static const attCfg_t datcAttCfg = {
    15, /* ATT server service discovery connection idle timeout in seconds */
    241, /* desired ATT MTU */
    ATT_MAX_TRANS_TIMEOUT, /* transcation timeout in seconds */
    4 /* number of queued prepare writes supported by server */
};

/*! local IRK */
static uint8_t localIrk[] = { 0xA6, 0xD9, 0xFF, 0x70, 0xD6, 0x1E, 0xF0, 0xA4,
                              0x46, 0x5F, 0x8D, 0x68, 0x19, 0xF3, 0xB4, 0x96 };

/**************************************************************************************************
  ATT Client Discovery Data
**************************************************************************************************/

/*! Discovery states:  enumeration of services to be discovered */
enum {
    DATC_DISC_GATT_SVC, /*! GATT service */
    DATC_DISC_GAP_SVC, /*! GAP service */
    DATC_DISC_WP_SVC, /*! Arm Ltd. proprietary service */
    DATC_DISC_WDXC_SCV, /*! Arm Ltd. Wireless Data Exchange service */
    DATC_DISC_SVC_MAX /*! Discovery complete */
};

/*! the Client handle list, datcCb.hdlList[], is set as follows:
 *
 *  ------------------------------- <- DATC_DISC_GATT_START
 *  | GATT svc changed handle     |
 *  -------------------------------
 *  | GATT svc changed ccc handle |
 *  ------------------------------- <- DATC_DISC_GAP_START
 *  | GAP central addr res handle |
 *  -------------------------------
 *  | GAP RPA Only handle         |
 *  ------------------------------- <- DATC_DISC_WP_START
 *  | WP handles                  |
 *  | ...                         |
 *  -------------------------------
 */

/*! Start of each service's handles in the the handle list */
#define DATC_DISC_GATT_START 0
#define DATC_DISC_GAP_START (DATC_DISC_GATT_START + GATT_HDL_LIST_LEN)
#define DATC_DISC_WP_START (DATC_DISC_GAP_START + GAP_HDL_LIST_LEN)
#define DATC_DISC_WDXC_START (DATC_DISC_WP_START + WPC_P1_HDL_LIST_LEN)
#define DATC_DISC_HDL_LIST_LEN (DATC_DISC_WDXC_START + WDXC_HDL_LIST_LEN)

/*! Pointers into handle list for each service's handles */
static uint16_t *pDatcGattHdlList[DM_CONN_MAX];
static uint16_t *pDatcGapHdlList[DM_CONN_MAX];
static uint16_t *pDatcWpHdlList[DM_CONN_MAX];
static uint16_t *pDatcWdxHdlList[DM_CONN_MAX];

/* LESC OOB configuration */
static dmSecLescOobCfg_t *datcOobCfg;

/**************************************************************************************************
  ATT Client Configuration Data
**************************************************************************************************/

/*
 * Data for configuration after service discovery
 */

/* Default value for CCC indications */
const uint8_t datcCccIndVal[2] = { UINT16_TO_BYTES(ATT_CLIENT_CFG_INDICATE) };

/* Default value for CCC notifications */
const uint8_t datcCccNtfVal[2] = { UINT16_TO_BYTES(ATT_CLIENT_CFG_NOTIFY) };

/* Default value for Client Supported Features (enable Robust Caching) */
const uint8_t datcCsfVal[1] = { ATTS_CSF_ROBUST_CACHING };

/* List of characteristics to configure after service discovery */
static const attcDiscCfg_t datcDiscCfgList[] = {
    /* Write:  GATT service changed ccc descriptor */
    { datcCccIndVal, sizeof(datcCccIndVal), (GATT_SC_CCC_HDL_IDX + DATC_DISC_GATT_START) },

    /* Write:  GATT client supported features */
    { datcCsfVal, sizeof(datcCsfVal), (GATT_CSF_HDL_IDX + DATC_DISC_GATT_START) },

    /* Write:  Proprietary data service changed ccc descriptor */
    { datcCccNtfVal, sizeof(datcCccNtfVal), (WPC_P1_NA_CCC_HDL_IDX + DATC_DISC_WP_START) },

    /* Write:  WDXC ccc descriptors */
    { datcCccNtfVal, sizeof(datcCccNtfVal), (WDXC_DC_CCC_HDL_IDX + DATC_DISC_WDXC_START) },
    { datcCccNtfVal, sizeof(datcCccNtfVal), (WDXC_FTC_CCC_HDL_IDX + DATC_DISC_WDXC_START) },
    { datcCccNtfVal, sizeof(datcCccNtfVal), (WDXC_FTD_CCC_HDL_IDX + DATC_DISC_WDXC_START) },
    { datcCccNtfVal, sizeof(datcCccNtfVal), (WDXC_AU_CCC_HDL_IDX + DATC_DISC_WDXC_START) },
};

/* Characteristic configuration list length */
#define DATC_DISC_CFG_LIST_LEN (sizeof(datcDiscCfgList) / sizeof(attcDiscCfg_t))

/* sanity check:  make sure configuration list length is <= handle list length */
WSF_CT_ASSERT(DATC_DISC_CFG_LIST_LEN <= DATC_DISC_HDL_LIST_LEN);

extern void setAdvTxPower(void);

/*************************************************************************************************/
/*!
 *  \brief  Reset the OTA state.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcResetOTAState(void)
{
    int i;
    for (i = 0; i < DM_CONN_MAX; i++) {
        datcCb.sendingFile[i] = FALSE;
        datcCb.fileVerified[i] = FALSE;
        datcCb.blockOffset[i] = BLOCK_OFFSET_INIT;
    }
}

/*************************************************************************************************/
/*!
 *  \brief  Application DM callback.
 *
 *  \param  pDmEvt  DM callback event
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcDmCback(dmEvt_t *pDmEvt)
{
    dmEvt_t *pMsg;
    uint16_t len;
    uint16_t reportLen;

    if (pDmEvt->hdr.event == DM_SEC_ECC_KEY_IND) {
        DmSecSetEccKey(&pDmEvt->eccMsg.data.key);

        /* If the local device sends OOB data. */
        if (datcSendOobData) {
            uint8_t oobLocalRandom[SMP_RAND_LEN];
            SecRand(oobLocalRandom, SMP_RAND_LEN);
            DmSecCalcOobReq(oobLocalRandom, pDmEvt->eccMsg.data.key.pubKey_x);
        }
    } else if (pDmEvt->hdr.event == DM_SEC_CALC_OOB_IND) {
        if (datcOobCfg == NULL) {
            datcOobCfg = WsfBufAlloc(sizeof(dmSecLescOobCfg_t));
        }

        if (datcOobCfg) {
            Calc128Cpy(datcOobCfg->localConfirm, pDmEvt->oobCalcInd.confirm);
            Calc128Cpy(datcOobCfg->localRandom, pDmEvt->oobCalcInd.random);
        }
    } else {
        len = DmSizeOfEvt(pDmEvt);

        if (pDmEvt->hdr.event == DM_SCAN_REPORT_IND) {
            reportLen = pDmEvt->scanReport.len;
        } else {
            reportLen = 0;
        }

        if ((pMsg = WsfMsgAlloc(len + reportLen)) != NULL) {
            memcpy(pMsg, pDmEvt, len);
            if (pDmEvt->hdr.event == DM_SCAN_REPORT_IND) {
                pMsg->scanReport.pData = (uint8_t *)((uint8_t *)pMsg + len);
                memcpy(pMsg->scanReport.pData, pDmEvt->scanReport.pData, reportLen);
            }
            WsfMsgSend(datcCb.handlerId, pMsg);
        }
    }
}

/*************************************************************************************************/
/*!
 *  \brief  Application  ATT callback.
 *
 *  \param  pEvt    ATT callback event
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcAttCback(attEvt_t *pEvt)
{
    attEvt_t *pMsg;

    if ((pMsg = WsfMsgAlloc(sizeof(attEvt_t) + pEvt->valueLen)) != NULL) {
        memcpy(pMsg, pEvt, sizeof(attEvt_t));
        pMsg->pValue = (uint8_t *)(pMsg + 1);
        memcpy(pMsg->pValue, pEvt->pValue, pEvt->valueLen);
        WsfMsgSend(datcCb.handlerId, pMsg);
    }
}

/*************************************************************************************************/
/*!
 *  \brief  Restart scanning handler.
 *
 *  \param  None.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcRestartScanningHandler(void)
{
    datcCb.autoConnect = TRUE;
    datcConnInfo.doConnect = FALSE;
    AppScanStart(datcMasterCfg.discMode, datcMasterCfg.scanType, datcMasterCfg.scanDuration);
}

/*************************************************************************************************/
/*!
 *  \brief  Restart scanning.
 *
 *  \param  None.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcRestartScanning(void)
{
    /* Start the scanning start timer */
    WsfTimerStartMs(&datcCb.scanTimer, SCAN_START_MS);
}

/*************************************************************************************************/
/*!
 *  \brief  Perform actions on scan start.
 *
 *  \param  pMsg    Pointer to DM callback event message.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcScanStart(dmEvt_t *pMsg)
{
    if (pMsg->hdr.status == HCI_SUCCESS) {
        datcCb.scanning = TRUE;
    }
}

/*************************************************************************************************/
/*!
 *  \brief  Perform actions on scan stop.
 *
 *  \param  pMsg    Pointer to DM callback event message.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcScanStop(dmEvt_t *pMsg)
{
    if (pMsg->hdr.status == HCI_SUCCESS) {
        datcCb.scanning = FALSE;
        datcCb.autoConnect = FALSE;

        /* Open connection */
        if (datcConnInfo.doConnect) {
            AppConnOpen(datcConnInfo.addrType, datcConnInfo.addr, datcConnInfo.dbHdl);
            datcConnInfo.doConnect = FALSE;
        }
    }
}

/*************************************************************************************************/
/*!
 *  \brief  Handle a scan report.
 *
 *  \param  pMsg    Pointer to DM callback event message.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcScanReport(dmEvt_t *pMsg)
{
    uint8_t *pData;
    appDbHdl_t dbHdl;
    bool_t connect = FALSE;

    /* disregard if not scanning or autoconnecting */
    if (!datcCb.scanning || !datcCb.autoConnect) {
        return;
    }

    /* if we already have a bond with this device then connect to it */
    if ((dbHdl = AppDbFindByAddr(pMsg->scanReport.addrType, pMsg->scanReport.addr)) !=
        APP_DB_HDL_NONE) {
        /* if this is a directed advertisement where the initiator address is an RPA */
        if (DM_RAND_ADDR_RPA(pMsg->scanReport.directAddr, pMsg->scanReport.directAddrType)) {
            /* resolve direct address to see if it's addressed to us */
            AppMasterResolveAddr(pMsg, dbHdl, APP_RESOLVE_DIRECT_RPA);
        } else {
            connect = TRUE;
        }
    } else if (DM_RAND_ADDR_RPA(pMsg->scanReport.addr, pMsg->scanReport.addrType)) {
        /* if the peer device uses an RPA */
        /* resolve advertiser's RPA to see if we already have a bond with this device */
        AppMasterResolveAddr(pMsg, APP_DB_HDL_NONE, APP_RESOLVE_ADV_RPA);
    }
    /* Search for "OTAS" name */
    if (!connect && ((pData = DmFindAdType(DM_ADV_TYPE_LOCAL_NAME, pMsg->scanReport.len,
                                           pMsg->scanReport.pData)) != NULL)) {
        /* check length and device name */
        if (pData[DM_AD_LEN_IDX] >= 4 && (pData[DM_AD_DATA_IDX] == 'O') &&
            (pData[DM_AD_DATA_IDX + 1] == 'T') && (pData[DM_AD_DATA_IDX + 2] == 'A') &&
            (pData[DM_AD_DATA_IDX + 3] == 'S')) {
            connect = TRUE;
        }
    }

    if (connect) {
        /* stop scanning and connect */
        datcCb.autoConnect = FALSE;
        AppScanStop();

        /* Store peer information for connect on scan stop */
        datcConnInfo.addrType = DmHostAddrType(pMsg->scanReport.addrType);
        memcpy(datcConnInfo.addr, pMsg->scanReport.addr, sizeof(bdAddr_t));
        datcConnInfo.dbHdl = dbHdl;
        datcConnInfo.doConnect = TRUE;
    }
}

/*************************************************************************************************/
/*!
 *  \brief  Perform UI actions on connection open.
 *
 *  \param  pMsg    Pointer to DM callback event message.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcOpen(dmEvt_t *pMsg)
{
    datcResetOTAState();
}

/*************************************************************************************************/
/*!
 *  \brief  Process a received ATT notification.
 *
 *  \param  pMsg    Pointer to ATT callback event message.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcValueNtf(attEvt_t *pMsg)
{
    /* print received message */
    APP_TRACE_INFO0((const char *)pMsg->pValue);
}

/*************************************************************************************************/
/*!
 *  \brief  Set up procedures that need to be performed after device reset.
 *
 *  \param  pMsg    Pointer to DM callback event message.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcSetup(dmEvt_t *pMsg)
{
    datcCb.scanning = FALSE;
    datcCb.autoConnect = FALSE;
    datcConnInfo.doConnect = FALSE;
    datcCb.restoringResList = FALSE;

    DmConnSetConnSpec((hciConnSpec_t *)&datcConnCfg);
}

/*************************************************************************************************/
/*!
 *  \brief  Begin restoring the resolving list.
 *
 *  \param  pMsg    Pointer to DM callback event message.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcRestoreResolvingList(dmEvt_t *pMsg)
{
    /* Restore first device to resolving list in Controller. */
    datcCb.resListRestoreHdl = AppAddNextDevToResList(APP_DB_HDL_NONE);

    if (datcCb.resListRestoreHdl == APP_DB_HDL_NONE) {
        /* No device to restore.  Setup application. */
        datcSetup(pMsg);
    } else {
        datcCb.restoringResList = TRUE;
    }
}

/*************************************************************************************************/
/*!
*  \brief  Handle add device to resolving list indication.
 *
 *  \param  pMsg    Pointer to DM callback event message.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcPrivAddDevToResListInd(dmEvt_t *pMsg)
{
    /* Check if in the process of restoring the Device List from NV */
    if (datcCb.restoringResList) {
        /* Retore next device to resolving list in Controller. */
        datcCb.resListRestoreHdl = AppAddNextDevToResList(datcCb.resListRestoreHdl);

        if (datcCb.resListRestoreHdl == APP_DB_HDL_NONE) {
            /* No additional device to restore. Setup application. */
            datcSetup(pMsg);
        }
    }
}

/*************************************************************************************************/
/*!
 *  \brief  GAP service discovery has completed.
 *
 *  \param  connId    Connection identifier.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcDiscGapCmpl(dmConnId_t connId)
{
    appDbHdl_t dbHdl;

    /* if RPA Only attribute found on peer device */
    if ((pDatcGapHdlList[connId - 1][GAP_RPAO_HDL_IDX] != ATT_HANDLE_NONE) &&
        ((dbHdl = AppDbGetHdl(connId)) != APP_DB_HDL_NONE)) {
        /* update DB */
        AppDbSetPeerRpao(dbHdl, TRUE);
        AppDbNvmStorePeerRpao(dbHdl);
    }
}

/*************************************************************************************************/
/*!
 *  \brief  WDXC File Transfer Data Callback.
 *
 *  \param  connId    Connection ID.
 *  \param  fileHdl   Handle of the file.
 *  \param  len       length of pData in bytes.
 *  \param  pData     File data.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcWdxcFtdCallback(dmConnId_t connId, uint16_t fileHdl, uint16_t len, uint8_t *pData)
{
}

/*************************************************************************************************/
/*!
 *  \brief  Send file header.
 *
 *  \param  connId    Connection identifier.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void sendFileHeader(dmConnId_t connId)
{
    if (pDatcWpHdlList[connId - 1][WPC_P1_DAT_HDL_IDX] != ATT_HANDLE_NONE) {
        AttcWriteCmd(connId, pDatcWpHdlList[connId - 1][WPC_P1_DAT_HDL_IDX], sizeof(fileHeader_t),
                     (uint8_t *)&fileHeader);
    }
}

/*************************************************************************************************/
/*!
 *  \brief  Send a block of file data to the peer. Combines the address with the data.
 *
 *  \param  connId    Connection identifier.
 *  \param  address   Address of the block.
 *  \param  len       Length of the data.
 *  \param  pData     Pointer to the data to send.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcSendBlock(dmConnId_t connId, uint32_t address, uint32_t len, uint8_t *pData)
{
    uint8_t *addrData = WsfBufAlloc(datcCb.blockSize + sizeof(uint32_t));

    /* Insert the address into the block */
    memcpy(addrData, &address, sizeof(uint32_t));
    memcpy(&addrData[sizeof(uint32_t)], pData, len);

    // APP_TRACE_INFO2("Sending addr: 0x%08X len: 0x%04X", address, len);

    /* Send the address and data, add the length of the address to the length */
    WdxcFtdSendBlock(connId, len + sizeof(uint32_t), addrData);

    /* Clear out the buf->free field to prevent un-intended assertion in WsfBufFree */
    addrData[4] = 0;
    addrData[5] = 0;
    addrData[6] = 0;
    addrData[7] = 0;

    WsfBufFree(addrData);

    /* Increment the address of the data that we're sending */
    datcCb.blockOffset[connId - 1] += len;
}

/*************************************************************************************************/
/*!
 *  \brief  WDXC File Transfer Control Callback.
 *
 *  \param  connId    Connection ID.
 *  \param  op        Control operation.
 *  \param  status    Status of operation.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcWdxcFtcCallback(dmConnId_t connId, uint16_t handle, uint8_t op, uint8_t status)
{
    APP_TRACE_INFO2("FTC op: %d status: %d", op, status);

    if (op == WDX_FTC_OP_PUT_RSP) {
        /* Start timer */
        APP_TRACE_INFO0(">>> Starting file transfer <<<\n");

        MXC_TMR_SW_Start(MXC_TMR2);
        datcCb.sendingFile[connId - 1] = TRUE;
        uint32_t address = datcCb.blockOffset[connId - 1] - BLOCK_OFFSET_INIT;
        datcSendBlock(connId, address, datcCb.blockSize, (uint8_t *)&datcCb.fileData[address]);

    } else if (op == WDX_FTC_OP_EOF) {
        if (handle == WDX_FLIST_HANDLE) {
            /* on discovery completion we can send the header */
            sendFileHeader(connId);
            /* File discovery complete */
            APP_TRACE_INFO0(">>> File discovery complete <<<\n");
        } else {
            /* Stop timer, calculate time and Bps */
            uint32_t usec = MXC_TMR_SW_Stop(MXC_TMR2);
            APP_TRACE_INFO1(">>> File transfer complete %d us <<<\n", usec);
            APP_TRACE_INFO3("file_size = %d usec = %d bps = %d\n", FILE_SIZE, usec,
                            ((FILE_SIZE * 1000) / (usec / 1000)) * 8);
            datcCb.sendingFile[connId - 1] = FALSE;
        }
    } else if (op == WDX_FTC_OP_VERIFY_RSP) {
        APP_TRACE_INFO1(">>> Verify complete status: %d <<<\n", status);
        if (status)
            datcCb.fileVerified[connId - 1] = FALSE;
        else
            datcCb.fileVerified[connId - 1] = TRUE;
    }
}
/*************************************************************************************************/
/*!
 *  \brief  Button press callback.
 *
 *  \param  btn    Button press.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcBtnCback(uint8_t btn)
{
    dmConnId_t connId = datcCb.btnConnId;
    dmConnId_t connIdList[DM_CONN_MAX];
    uint8_t numConnections = AppConnOpenList(connIdList);

    /* button actions when connected */
    if (numConnections > 0) {
        switch (btn) {
        case APP_UI_BTN_1_SHORT:
            if (numConnections < DM_CONN_MAX - 1) {
                if (datcCb.scanning) { /* if scanning cancel scanning */
                    AppScanStop();
                } else if (!datcCb.autoConnect) { /* else auto connect */
                    datcRestartScanning();
                }
            } else {
                APP_TRACE_INFO0("datcBtnCback: Max connections reached.");
            }
            break;

        case APP_UI_BTN_1_MED:
            /* Increment connection ID used in button presses */
            if (++datcCb.btnConnId > DM_CONN_MAX) {
                datcCb.btnConnId = 1;
            }
            APP_TRACE_INFO1("ConnId for Button Press: %d", datcCb.btnConnId);
            break;

        case APP_UI_BTN_1_LONG:
            /* disconnect */
            AppConnClose(connId);
            break;

#if (BT_VER > 8)
        case APP_UI_BTN_1_EX_LONG: {
            static uint32_t coded_phy_cnt = 0;
            /* Toggle PHY Test Mode */
            coded_phy_cnt++;
            switch (coded_phy_cnt & 0x3) {
            case 0:
                /* 1M PHY */
                APP_TRACE_INFO0("1 MBit TX and RX PHY Requested");
                DmSetPhy(connId, HCI_ALL_PHY_ALL_PREFERENCES, HCI_PHY_LE_1M_BIT, HCI_PHY_LE_1M_BIT,
                         HCI_PHY_OPTIONS_NONE);
                break;
            case 1:
                /* 2M PHY */
                APP_TRACE_INFO0("2 MBit TX and RX PHY Requested");
                DmSetPhy(connId, HCI_ALL_PHY_ALL_PREFERENCES, HCI_PHY_LE_2M_BIT, HCI_PHY_LE_2M_BIT,
                         HCI_PHY_OPTIONS_NONE);
                break;
            case 2:
                /* Coded S2 PHY */
                APP_TRACE_INFO0("LE Coded S2 TX and RX PHY Requested");
                DmSetPhy(connId, HCI_ALL_PHY_ALL_PREFERENCES, HCI_PHY_LE_CODED_BIT,
                         HCI_PHY_LE_CODED_BIT, HCI_PHY_OPTIONS_S2_PREFERRED);
                break;
            case 3:
                /* Coded S8 PHY */
                APP_TRACE_INFO0("LE Coded S8 TX and RX PHY Requested");
                DmSetPhy(connId, HCI_ALL_PHY_ALL_PREFERENCES, HCI_PHY_LE_CODED_BIT,
                         HCI_PHY_LE_CODED_BIT, HCI_PHY_OPTIONS_S8_PREFERRED);
                break;
            }
            break;
        }
#endif /* BT_VER */

        case APP_UI_BTN_2_SHORT:
            if (datcCb.discState[connId - 1] > DATC_DISC_WDXC_SCV) {
                WdxcDiscoverFiles(connId, datcCb.fileList[connId - 1], DATC_WDXC_MAX_FILES);
                datcCb.blockSize = AttGetMtu(connId);

                /* Subtract for the address and message overhead */
                datcCb.blockSize = datcCb.blockSize - 8;
                if (datcCb.blockSize > BLOCK_SIZE) {
                    datcCb.blockSize = BLOCK_SIZE;
                }
            }
            break;

        case APP_UI_BTN_2_MED:
            if ((datcCb.discState[connId - 1] > DATC_DISC_WDXC_SCV) &&
                (datcCb.sendingFile[connId - 1] == FALSE)) {
                /* Start the WDXC data stream */
                datcCb.blockOffset[connId - 1] = BLOCK_OFFSET_INIT;

                /* Put file request */
                WdxcFtcSendPutReq(connId, datcCb.fileList[connId - 1][0].handle, BLOCK_OFFSET_INIT,
                                  FILE_SIZE, BLOCK_OFFSET_INIT + FILE_SIZE, 0);
            }
            break;

        case APP_UI_BTN_2_LONG:
            if (datcCb.discState[connId - 1] > DATC_DISC_WDXC_SCV) {
                /* Send verification request */
                WdxcFtcSendVerifyFile(connId, datcCb.fileList[connId - 1][0].handle);
            }
            break;

        case APP_UI_BTN_2_EX_LONG:
            if (datcCb.fileVerified[connId - 1]) {
                /* Send Disconnect and Reset request to apply firmware update */
                WdxcDcSendDisconnectAndReset(connId);
                datcCb.fileVerified[connId - 1] = FALSE;
            }
            break;
        default:
            APP_TRACE_INFO0(" - No action assigned");
            break;
        }
    } else { /* button actions when not connected */
        switch (btn) {
        case APP_UI_BTN_1_SHORT:
            if (datcCb.scanning) { /* if scanning cancel scanning */
                AppScanStop();
            } else if (!datcCb.autoConnect) { /* else auto connect */
                datcRestartScanning();
            }
            break;

        case APP_UI_BTN_1_MED:
            /* Increment connection ID buttons apply to */
            if (++datcCb.btnConnId > DM_CONN_MAX) {
                datcCb.btnConnId = 1;
            }
            APP_TRACE_INFO1("ConnID for Button Press: %d", datcCb.btnConnId);
            break;

        case APP_UI_BTN_1_LONG:
            /* clear all bonding info */
            AppClearAllBondingInfo();
            AppDbNvmDeleteAll();
            break;

        case APP_UI_BTN_1_EX_LONG:
            /* add RPAO characteristic to GAP service -- needed only when DM Privacy enabled */
            SvcCoreGapAddRpaoCh();
            break;

        case APP_UI_BTN_2_EX_LONG:
            /* enable device privacy -- start generating local RPAs every 15 minutes */
            DmDevPrivStart(15 * 60);

            /* set Scanning filter policy to accept directed advertisements with RPAs */
            DmDevSetFilterPolicy(DM_FILT_POLICY_MODE_SCAN, HCI_FILT_RES_INIT);
            break;

        default:
            APP_TRACE_INFO0(" - No action assigned");
            break;
        }
    }
}

/*************************************************************************************************/
/*!
 *  \brief  Discovery callback.
 *
 *  \param  connId    Connection identifier.
 *  \param  status    Service or configuration status.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcDiscCback(dmConnId_t connId, uint8_t status)
{
    switch (status) {
    case APP_DISC_INIT:
        /* set handle list when initialization requested */
        AppDiscSetHdlList(connId, datcCb.hdlListLen, datcCb.hdlList[connId - 1]);
        break;

    case APP_DISC_READ_DATABASE_HASH:
        /* Read peer's database hash */
        AppDiscReadDatabaseHash(connId);
        break;

    case APP_DISC_SEC_REQUIRED:
        /* initiate security */
        AppMasterSecurityReq(connId);
        break;

    case APP_DISC_START:
        /* initialize discovery state */
        datcCb.discState[connId - 1] = DATC_DISC_GATT_SVC;

        /* store possible change in cache by hash */
        AppDbNvmStoreCacheByHash(AppDbGetHdl(connId));

        /* discover GATT service */
        GattDiscover(connId, pDatcGattHdlList[connId - 1]);
        break;

    case APP_DISC_FAILED:
        if (pAppCfg->abortDisc) {
            /* if discovery failed for any service then disconnect */
            if (datcCb.discState[connId - 1] < DATC_DISC_SVC_MAX) {
                AppConnClose(connId);
                break;
            }
        }
        /* Else falls through. */

    case APP_DISC_CMPL:
        /* next discovery state */
        datcCb.discState[connId - 1]++;

        if (datcCb.discState[connId - 1] == DATC_DISC_GAP_SVC) {
            /* discover GAP service */
            GapDiscover(connId, pDatcGapHdlList[connId - 1]);
        } else if (datcCb.discState[connId - 1] == DATC_DISC_WP_SVC) {
            /* discover proprietary data service */
            WpcP1Discover(connId, pDatcWpHdlList[connId - 1]);
        } else if (datcCb.discState[connId - 1] == DATC_DISC_WDXC_SCV) {
            WdxcWdxsDiscover(connId, pDatcWdxHdlList[connId - 1]);
        } else {
            /* discovery complete */
            AppDiscComplete(connId, APP_DISC_CMPL);

            /* GAP service discovery completed */
            datcDiscGapCmpl(connId);

            /* store cached handle list in NVM */
            AppDbNvmStoreHdlList(AppDbGetHdl(connId));

            /* start configuration */
            AppDiscConfigure(connId, APP_DISC_CFG_START, DATC_DISC_CFG_LIST_LEN,
                             (attcDiscCfg_t *)datcDiscCfgList, DATC_DISC_HDL_LIST_LEN,
                             datcCb.hdlList[connId - 1]);
        }
        break;

    case APP_DISC_CFG_START:
    case APP_DISC_CFG_CONN_START:
        /* start configuration */
        WdxcStoreAttrHandles(connId, pDatcWdxHdlList[connId - 1]);
        datcCb.discState[connId - 1] = DATC_DISC_SVC_MAX;
        AppDiscConfigure(connId, APP_DISC_CFG_START, DATC_DISC_CFG_LIST_LEN,
                         (attcDiscCfg_t *)datcDiscCfgList, DATC_DISC_HDL_LIST_LEN,
                         datcCb.hdlList[connId - 1]);
        break;

    case APP_DISC_CFG_CMPL:
        AppDiscComplete(connId, status);
        break;

    default:
        break;
    }
}

/*************************************************************************************************/
/*!
 *  \brief  Process messages from the event handler.
 *
 *  \param  pMsg    Pointer to message.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcProcMsg(dmEvt_t *pMsg)
{
    uint8_t uiEvent = APP_UI_NONE;

    switch (pMsg->hdr.event) {
    case ATTC_HANDLE_VALUE_NTF:
        datcValueNtf((attEvt_t *)pMsg);
        break;

    case ATTC_WRITE_CMD_RSP:
    case ATTC_WRITE_RSP: {
        dmConnId_t connId = (dmConnId_t)pMsg->hdr.param;

        if ((((attEvt_t *)pMsg)->hdr.status == ATT_SUCCESS) &&
            (((attEvt_t *)pMsg)->handle == pDatcWdxHdlList[connId - 1][WDXC_FTD_HDL_IDX])) {
            if (datcCb.sendingFile[connId - 1] == TRUE) {
                uint32_t tempBlockSize;
                if ((datcCb.blockOffset[connId - 1] + datcCb.blockSize) > FILE_SIZE) {
                    tempBlockSize = FILE_SIZE - datcCb.blockOffset[connId - 1];
                } else {
                    tempBlockSize = datcCb.blockSize;
                }

                /* Keep writing the file */
                uint32_t address = datcCb.blockOffset[connId - 1] - BLOCK_OFFSET_INIT;
                datcSendBlock(connId, address, tempBlockSize, (uint8_t *)&datcCb.fileData[address]);
            }
        }
        break;
    }

    case DM_RESET_CMPL_IND:
        AttsCalculateDbHash();
        DmSecGenerateEccKeyReq();
        AppDbNvmReadAll();
        setAdvTxPower();
        datcRestoreResolvingList(pMsg);
        datcRestartScanning();
        uiEvent = APP_UI_RESET_CMPL;
        break;

    case DM_SCAN_START_IND:
        datcScanStart(pMsg);
        uiEvent = APP_UI_SCAN_START;
        break;

    case DM_SCAN_STOP_IND:
        datcScanStop(pMsg);
        uiEvent = APP_UI_SCAN_STOP;
        break;

    case DM_SCAN_REPORT_IND:
        datcScanReport(pMsg);
        break;

    case DM_CONN_OPEN_IND:
        datcOpen(pMsg);
        uiEvent = APP_UI_CONN_OPEN;
        break;

    case DM_CONN_CLOSE_IND:
        APP_TRACE_INFO2("Connection closed status 0x%x, reason 0x%x", pMsg->connClose.status,
                        pMsg->connClose.reason);
        switch (pMsg->connClose.reason) {
        case HCI_ERR_CONN_TIMEOUT:
            APP_TRACE_INFO0(" TIMEOUT");
            break;
        case HCI_ERR_LOCAL_TERMINATED:
            APP_TRACE_INFO0(" LOCAL TERM");
            break;
        case HCI_ERR_REMOTE_TERMINATED:
            APP_TRACE_INFO0(" REMOTE TERM");
            break;
        case HCI_ERR_CONN_FAIL:
            APP_TRACE_INFO0(" FAIL ESTABLISH");
            break;
        case HCI_ERR_MIC_FAILURE:
            APP_TRACE_INFO0(" MIC FAILURE");
            break;
        }
        uiEvent = APP_UI_CONN_CLOSE;
        datcRestartScanning();
        break;

    case DM_SEC_PAIR_CMPL_IND:
        DmSecGenerateEccKeyReq();
        AppDbNvmStoreBond(AppDbGetHdl((dmConnId_t)pMsg->hdr.param));
        uiEvent = APP_UI_SEC_PAIR_CMPL;
        break;

    case DM_SEC_PAIR_FAIL_IND:
        DmSecGenerateEccKeyReq();
        uiEvent = APP_UI_SEC_PAIR_FAIL;
        break;

    case DM_SEC_ENCRYPT_IND:
        uiEvent = APP_UI_SEC_ENCRYPT;
        break;

    case DM_SEC_ENCRYPT_FAIL_IND:
        uiEvent = APP_UI_SEC_ENCRYPT_FAIL;
        break;

    case DM_SEC_AUTH_REQ_IND:

        if (pMsg->authReq.oob) {
            dmConnId_t connId = (dmConnId_t)pMsg->hdr.param;

            /* TODO: Perform OOB Exchange with the peer. */

            /* TODO: Fill datsOobCfg peerConfirm and peerRandom with value passed out of band */

            if (datcOobCfg != NULL) {
                DmSecSetOob(connId, datcOobCfg);
            }

            DmSecAuthRsp(connId, 0, NULL);
        } else {
            AppHandlePasskey(&pMsg->authReq);
        }
        break;

    case DM_SEC_COMPARE_IND:
        AppHandleNumericComparison(&pMsg->cnfInd);
        break;

    case DM_ADV_NEW_ADDR_IND:
        break;

    case DM_PRIV_ADD_DEV_TO_RES_LIST_IND:
        datcPrivAddDevToResListInd(pMsg);
        break;

    case DM_PRIV_CLEAR_RES_LIST_IND:
        APP_TRACE_INFO1("Clear resolving list status 0x%02x", pMsg->hdr.status);
        break;

#if (BT_VER > 8)
    case DM_PHY_UPDATE_IND:
        APP_TRACE_INFO2("DM_PHY_UPDATE_IND - RX: %d, TX: %d", pMsg->phyUpdate.rxPhy,
                        pMsg->phyUpdate.txPhy);
        break;
#endif /* BT_VER */

    case SCAN_START_EVT:
        datcRestartScanningHandler();
        break;

    default:
        break;
    }

    if (uiEvent != APP_UI_NONE) {
        AppUiAction(uiEvent);
    }
}

// http://home.thep.lu.se/~bjorn/crc/
/*************************************************************************************************/
/*!
 *  \brief  Create the CRC32 table.
 *
 *  \param  r       Index into the table
 *
 *  \return None.
 */
/*************************************************************************************************/
uint32_t crc32_for_byte(uint32_t r)
{
    for (int j = 0; j < 8; ++j) r = (r & 1 ? 0 : (uint32_t)0xEDB88320L) ^ r >> 1;
    return r ^ (uint32_t)0xFF000000L;
}

/*************************************************************************************************/
/*!
 *  \brief  Calculate the CRC32 value for the given buffer.
 *
 *  \param  data    Pointer to the data.
 *  \param  n_bytes Number of bytes in the buffer.
 *  \param  crc     Pointer to store the result.
 *
 *  \return None.
 */
/*************************************************************************************************/
static uint32_t table[0x100] = { 0 };
void crc32(const void *data, size_t n_bytes, uint32_t *crc)
{
    if (!*table) {
        for (size_t i = 0; i < 0x100; ++i) table[i] = crc32_for_byte(i);
    }
    for (size_t i = 0; i < n_bytes; ++i) {
        *crc = table[(uint8_t)*crc ^ ((uint8_t *)data)[i]] ^ *crc >> 8;
    }
}

/*************************************************************************************************/
/*!
 *  \brief  Application handler init function called during system initialization.
 *
 *  \param  handlerID  WSF handler ID.
 *
 *  \return None.
 */
/*************************************************************************************************/
void DatcHandlerInit(wsfHandlerId_t handlerId)
{
    uint8_t addr[6] = { 0 };
    APP_TRACE_INFO0("DatcHandlerInit");
    AppGetBdAddr(addr);
    APP_TRACE_INFO6("MAC Addr: %02x:%02x:%02x:%02x:%02x:%02x", addr[5], addr[4], addr[3], addr[2],
                    addr[1], addr[0]);

    /* store handler ID */
    datcCb.handlerId = handlerId;

    /* set handle list length */
    datcCb.hdlListLen = DATC_DISC_HDL_LIST_LEN;

    datcCb.btnConnId = 1;
    /* Set configuration pointers */
    pAppMasterCfg = (appMasterCfg_t *)&datcMasterCfg;
    pAppSecCfg = (appSecCfg_t *)&datcSecCfg;
    pAppDiscCfg = (appDiscCfg_t *)&datcDiscCfg;
    pAppCfg = (appCfg_t *)&datcAppCfg;
    pSmpCfg = (smpCfg_t *)&datcSmpCfg;
    pAttCfg = (attCfg_t *)&datcAttCfg;

    /* Initialize application framework */
    AppMasterInit();
    AppDiscInit();

    /* Set IRK for the local device */
    DmSecSetLocalIrk(localIrk);

    /* Set the pointer for the fw_update image */
    datcCb.fileData = (uint8_t *)&_binary_fw_update_bin_start;

    /* Calculate the update image CRC */
    datcCb.fileCRC = 0;
    crc32(datcCb.fileData, FILE_SIZE, &datcCb.fileCRC);
    fileHeader.fileCRC = datcCb.fileCRC;
    fileHeader.fileLen = FILE_SIZE;
    APP_TRACE_INFO2("File addr: %08X file size: %08X", (uint32_t)datcCb.fileData, FILE_SIZE);
    APP_TRACE_INFO1("Update File CRC: 0x%08X", datcCb.fileCRC);

    datcResetOTAState();

    /* Setup scan start timer */
    datcCb.scanTimer.handlerId = handlerId;
    datcCb.scanTimer.msg.event = SCAN_START_EVT;
}

/*************************************************************************************************/
/*!
 *  \brief     Platform button press handler.
 *
 *  \param[in] btnId  button ID.
 *  \param[in] state  button state. See ::PalBtnPos_t.
 *
 *  \return    None.
 */
/*************************************************************************************************/
static void btnPressHandler(uint8_t btnId, PalBtnPos_t state)
{
    if (btnId == 1) {
        /* Start/stop button timer */
        if (state == PAL_BTN_POS_UP) {
            /* Button Up, stop the timer, call the action function */
            unsigned btnUs = MXC_TMR_SW_Stop(BTN_1_TMR);
            if ((btnUs > 0) && (btnUs < BTN_SHORT_MS * 1000)) {
                AppUiBtnTest(APP_UI_BTN_1_SHORT);
            } else if (btnUs < BTN_MED_MS * 1000) {
                AppUiBtnTest(APP_UI_BTN_1_MED);
            } else if (btnUs < BTN_LONG_MS * 1000) {
                AppUiBtnTest(APP_UI_BTN_1_LONG);
            } else {
                AppUiBtnTest(APP_UI_BTN_1_EX_LONG);
            }
        } else {
            /* Button down, start the timer */
            MXC_TMR_SW_Start(BTN_1_TMR);
        }
    } else if (btnId == 2) {
        /* Start/stop button timer */
        if (state == PAL_BTN_POS_UP) {
            /* Button Up, stop the timer, call the action function */
            unsigned btnUs = MXC_TMR_SW_Stop(BTN_2_TMR);
            if ((btnUs > 0) && (btnUs < BTN_SHORT_MS * 1000)) {
                AppUiBtnTest(APP_UI_BTN_2_SHORT);
            } else if (btnUs < BTN_MED_MS * 1000) {
                AppUiBtnTest(APP_UI_BTN_2_MED);
            } else if (btnUs < BTN_LONG_MS * 1000) {
                AppUiBtnTest(APP_UI_BTN_2_LONG);
            } else {
                AppUiBtnTest(APP_UI_BTN_2_EX_LONG);
            }
        } else {
            /* Button down, start the timer */
            MXC_TMR_SW_Start(BTN_2_TMR);
        }
    } else {
        APP_TRACE_ERR0("Undefined button");
    }
}

/*************************************************************************************************/
/*!
 *  \brief  WSF event handler for application.
 *
 *  \param  event   WSF event mask.
 *  \param  pMsg    WSF message.
 *
 *  \return None.
 */
/*************************************************************************************************/
void DatcHandler(wsfEventMask_t event, wsfMsgHdr_t *pMsg)
{
    if (pMsg != NULL) {
        /* process ATT messages */
        if (pMsg->event <= ATT_CBACK_END) {
            /* process discovery-related ATT messages */
            AppDiscProcAttMsg((attEvt_t *)pMsg);

            /* process server-related ATT messages */
            AppServerProcAttMsg(pMsg);
        } else if (pMsg->event <= DM_CBACK_END) { /* process DM messages */
            /* process advertising and connection-related messages */
            AppMasterProcDmMsg((dmEvt_t *)pMsg);

            /* process security-related messages */
            AppMasterSecProcDmMsg((dmEvt_t *)pMsg);

            /* process discovery-related messages */
            AppDiscProcDmMsg((dmEvt_t *)pMsg);
        }

        /* perform profile and user interface-related operations */
        datcProcMsg((dmEvt_t *)pMsg);

        /* perform wdxc operations */
        WdxcProcMsg((wsfMsgHdr_t *)pMsg);
    }
}

/*************************************************************************************************/
/*!
 *  \brief  Initialize the pointers into the handle list.
 *
 *  \return None.
 */
/*************************************************************************************************/
static void datcInitSvcHdlList()
{
    uint8_t i;

    for (i = 0; i < DM_CONN_MAX; i++) {
        /*! Pointers into handle list for each service's handles */
        pDatcGattHdlList[i] = &datcCb.hdlList[i][DATC_DISC_GATT_START];
        pDatcGapHdlList[i] = &datcCb.hdlList[i][DATC_DISC_GAP_START];
        pDatcWpHdlList[i] = &datcCb.hdlList[i][DATC_DISC_WP_START];
        pDatcWdxHdlList[i] = &datcCb.hdlList[i][DATC_DISC_WDXC_START];
    }
}
/*************************************************************************************************/
/*!
 *  \brief  Start the application.
 *
 *  \return None.
 */
/*************************************************************************************************/
void DatcStart(void)
{
    /* Initialize handle pointers */
    datcInitSvcHdlList();

    /* Register for stack callbacks */
    DmRegister(datcDmCback);
    DmConnRegister(DM_CLIENT_ID_APP, datcDmCback);
    AttRegister(datcAttCback);

    /* Register for app framework button callbacks */
    AppUiBtnRegister(datcBtnCback);

    /* Register for app framework discovery callbacks */
    AppDiscRegister(datcDiscCback);

    /* Initialize attribute server database */
    SvcCoreAddGroup();

    /* Initialize the WDXC and set the WDXC application callbacks */
    WdxcInit(datcWdxcFtdCallback, datcWdxcFtcCallback);

#if (BT_VER > 8)
    DmPhyInit();
#endif /* BT_VER */

    WsfNvmInit();

    /* Initialize with button press handler */
    PalBtnInit(btnPressHandler);

    /* Reset the device */
    DmDevReset();
}
