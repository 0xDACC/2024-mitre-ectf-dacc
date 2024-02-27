/**
 * @file simple_flash.cpp
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief Safer simple flash interface
 * @version 0.1
 * @date 2024-02-01
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "simple_flash.h"

#include "flc.h"
#include "icc.h"
#include "nvic_table.h"

#include "errors.h"

static void FLC0_IRQHandler() {
    const uint32_t temp = MXC_FLC0->intr;
    if ((temp & MXC_F_FLC_INTR_DONE) != 0) {
        MXC_FLC0->intr &= ~MXC_F_FLC_INTR_DONE;
    }

    if ((temp & MXC_F_FLC_INTR_AF) != 0) {
        MXC_FLC0->intr &= ~MXC_F_FLC_INTR_AF;
    }
}

void flash_simple_init() {
    // Setup Flash
    MXC_NVIC_SetVector(FLC0_IRQn, FLC0_IRQHandler);
    NVIC_EnableIRQ(FLC0_IRQn);
    MXC_FLC_EnableInt(MXC_F_FLC_INTR_DONEIE | MXC_F_FLC_INTR_AFIE);
}

error_t flash_simple_erase_page(const uint32_t address) {
    int ret;
    MXC_ICC_Disable(MXC_ICC0);
    MXC_SYS_Crit_Enter();
    ret = MXC_FLC_PageErase(address);
    MXC_SYS_Crit_Exit();
    MXC_ICC_Enable(MXC_ICC0);
    return ret == E_NO_ERROR ? error_t::SUCCESS : error_t::ERROR;
}
