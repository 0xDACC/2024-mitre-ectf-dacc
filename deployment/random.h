/**
 * @file random.h
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief Random number generation
 * @version 0.1
 * @date 2024-02-26
 *
 * @copyright Copyright (c) 2024
 *
 */
#ifndef RANDOM
#define RANDOM

#include "errors.h"
#include "mxc.h"
#include "trng.h"
#include <stdint.h>

inline error_t random_init() {
    MXC_TRNG_Init();
    return error_t::SUCCESS;
}

inline void random_bytes(uint8_t *dest, uint32_t size) {
    if (dest == nullptr || size == 0) {
        return;
    }
    MXC_TRNG_Random(dest, size);
}
inline uint32_t random_int() {
    uint32_t ret = 0;
    MXC_TRNG_Random(reinterpret_cast<uint8_t *>(&ret), sizeof(ret));
    return ret;
}
inline uint32_t random_range(const uint32_t min, const uint32_t max) {
    if (min >= max) {
        return min;
    }
    return (random_int() % (max - min)) + min;
}

#endif /* RANDOM */
