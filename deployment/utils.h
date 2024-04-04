/**
 * @file utils.h
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief Utility functions
 * @version 0.1
 * @date 2024-02-29
 *
 * @copyright Copyright (c) 2024
 *
 */
#ifndef UTILS
#define UTILS

#include "tinycrypt/aes.h"
#include "tinycrypt/ctr_mode.h"

#include <stdint.h>

/**
 * @brief Unwrap a key from flash
 *
 * @param unwrapped_key The unwrapped key
 * @param wrapped_key The wrapped key
 * @param wrapper_key The key to unwrap with
 * @param wrapper_nonce The nonce to unwrap with
 */
inline void unwrap_aes_key(uint8_t *unwrapped_key,
                           const uint8_t *const wrapped_key,
                           const uint8_t *const wrapper_key,
                           uint8_t *const wrapper_nonce) {
    tc_aes_key_sched_struct aes_key = {};

    tc_aes128_set_encrypt_key(&aes_key, wrapper_key);
    tc_ctr_mode(unwrapped_key, 16, wrapped_key, 16, wrapper_nonce, &aes_key);
}
#endif /* UTILS */
