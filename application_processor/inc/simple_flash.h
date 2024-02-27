/**
 * @file simple_flash.h
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief Safer simple flash interface
 * @version 0.1
 * @date 2024-02-26
 *
 * @copyright Copyright (c) 2024
 *
 */

#ifndef SIMPLE_FLASH
#define SIMPLE_FLASH

#include "errors.h"
#include "flc.h"
#include "icc.h"
#include <stdint.h>

/**
 * @brief Initialize the Simple Flash Interface
 *
 * This function registers the interrupt for the flash system,
 * enables the interrupt, and disables ICC
 */
void flash_simple_init();

/**
 * @brief Flash Simple Erase Page
 *
 * @param address Address of flash page to erase
 * @return error_t Whether the erase was successful
 */
error_t flash_simple_erase_page(const uint32_t address);

/**
 * @brief Flash Simple Read
 *
 * @tparam T Type of buffer
 * @param address Address to read from
 * @param buffer Buffer to read into
 * @param size Size of buffer
 */
template <typename T>
void flash_simple_read(const uint32_t address, T *const buffer,
                       const uint32_t size) {
    MXC_ICC_Disable(MXC_ICC0);
    MXC_SYS_Crit_Enter();
    MXC_FLC_Read(address, buffer, size);
    MXC_SYS_Crit_Exit();
    MXC_ICC_Enable(MXC_ICC0);
}

/**
 * @brief Flash Simple Write
 *
 * @tparam T Type of buffer
 * @param address Address to write to
 * @param buffer Buffer to write from
 * @param size Size of buffer
 * @return error_t Whether the write was successful
 */

template <typename T>
error_t flash_simple_write(const uint32_t address, T *const buffer,
                           const uint32_t size) {
    int ret;
    MXC_ICC_Disable(MXC_ICC0);
    MXC_SYS_Crit_Enter();
    ret = MXC_FLC_Write(address, size, buffer);
    MXC_SYS_Crit_Exit();
    MXC_ICC_Enable(MXC_ICC0);
    return ret == E_NO_ERROR ? error_t::SUCCESS : error_t::ERROR;
}

#endif /* SIMPLE_FLASH */
