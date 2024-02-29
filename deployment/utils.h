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

#include <stdint.h>

/**
 * @brief Unwrap a key from flash
 *
 * @param unwrapped_key The unwrapped key
 * @param wrapped_key The wrapped key
 * @param wrapper_key The key to unwrap with
 * @param len The length of the key
 */
inline void unwrap_key(
	uint8_t *unwrapped_key, const uint8_t *const wrapped_key,
	const uint8_t *const wrapper_key, const uint32_t len) {
	for (uint32_t i = 0; i < len; ++i) {
		unwrapped_key[i] = wrapped_key[i] ^ wrapper_key[len - i];
	}
}
#endif /* UTILS */
