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

#include <stdio.h>

#include "flc.h"
#include "icc.h"
#include "nvic_table.h"

#include <stdio.h>

/**
 * @brief ISR for the Flash Controller
 *
 * This ISR allows for access to the flash through simple_flash to operate
 */
void FLC0_IRQHandler(void) {
    uint32_t temp;
    temp = MXC_FLC0->intr;
    if (temp & MXC_F_FLC_INTR_DONE) {
        MXC_FLC0->intr &= ~MXC_F_FLC_INTR_DONE;
        printf(" -> Interrupt! (Flash operation done)\n\n");
    }

    if (temp & MXC_F_FLC_INTR_AF) {
        MXC_FLC0->intr &= ~MXC_F_FLC_INTR_AF;
        printf(" -> Interrupt! (Flash access failure)\n\n");
    }
}

/**
 * @brief Initialize the Simple Flash Interface
 *
 * This function registers the interrupt for the flash system,
 * enables the interrupt, and disables ICC
 */
void flash_simple_init(void) {
    // Setup Flash
    MXC_NVIC_SetVector(FLC0_IRQn, FLC0_IRQHandler);
    NVIC_EnableIRQ(FLC0_IRQn);
    MXC_FLC_EnableInt(MXC_F_FLC_INTR_DONEIE | MXC_F_FLC_INTR_AFIE);
}

/**
 * @brief Flash Simple Erase Page
 *
 * @param address: uint32_t, address of flash page to erase
 *
 * @return int: return negative if failure, zero if success
 *
 * This function erases a page of flash such that it can be updated.
 * Flash memory can only be erased in a large block size called a page.
 * Once erased, memory can only be written one way e.g. 1->0.
 * In order to be re-written the entire page must be erased.
 */
int flash_simple_erase_page(uint32_t address) {
    int ret;
    MXC_ICC_Disable(MXC_ICC0);
    MXC_SYS_Crit_Enter();
    ret = MXC_FLC_PageErase(address);
    MXC_SYS_Crit_Exit();
    MXC_ICC_Enable(MXC_ICC0);
    return ret;
}

/**
 * @brief Flash Simple Read
 *
 * @param address: uint32_t, address of flash page to read
 * @param buffer: uint32_t*, pointer to buffer for data to be read into
 * @param size: uint32_t, number of bytes to read from flash
 *
 * This function reads data from the specified flash page into the buffer
 * with the specified amount of bytes
 */
void flash_simple_read(uint32_t address, uint32_t *buffer, uint32_t size) {
    MXC_ICC_Disable(MXC_ICC0);
    MXC_SYS_Crit_Enter();
    MXC_FLC_Read(address, buffer, size);
    MXC_SYS_Crit_Exit();
    MXC_ICC_Enable(MXC_ICC0);
}

/**
 * @brief Flash Simple Write
 *
 * @param address: uint32_t, address of flash page to write
 * @param buffer: uint32_t*, pointer to buffer to write data from
 * @param size: uint32_t, number of bytes to write from flash
 *
 * @return int: return negative if failure, zero if success
 *
 * This function writes data to the specified flash page from the buffer passed
 * with the specified amount of bytes. Flash memory can only be written in one
 * way e.g. 1->0. To rewrite previously written memory see the
 * flash_simple_erase_page documentation.
 */
int flash_simple_write(uint32_t address, uint32_t *buffer, uint32_t size) {
    int ret;
    MXC_ICC_Disable(MXC_ICC0);
    MXC_SYS_Crit_Enter();
    ret = MXC_FLC_Write(address, size, buffer);
    MXC_SYS_Crit_Exit();
    MXC_ICC_Enable(MXC_ICC0);
    return ret;
}
