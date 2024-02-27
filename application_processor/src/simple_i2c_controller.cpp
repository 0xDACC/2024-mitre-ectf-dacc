/**
 * @file simple_i2c_controller.cpp
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief Low Level I2C Communication Implementation
 * @version 0.1
 * @date 2024-02-01
 *
 * @copyright Copyright (c) 2024
 *
 */
#include "simple_i2c_controller.h"
#include "errors.h"
#include "i2c.h"
#include "mxc.h"
#include "packets.h"

namespace i2c {
error_t i2c_simple_controller_init() {

    // Initialize the I2C Interface
    const int error = MXC_I2C_Init(MXC_I2C1, true, 0);
    if (error != E_NO_ERROR) {
        printf("Failed to initialize I2C.\n");
        return error_t::ERROR;
    }

    MXC_I2C_SetFrequency(MXC_I2C1, I2C_FREQ);
    return error_t::SUCCESS;
}
} // namespace i2c
