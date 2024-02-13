/**
 * @file errors.h
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief Error Codes for functions
 * @version 0.1
 * @date 2024-02-01
 *
 * @copyright Copyright (c) 2024
 *
 */
#ifndef __ERRORS__
#define __ERRORS__

#if __cplusplus
extern "C" {
#endif

#include <stdint.h>

enum class error_t {
    SUCCESS = 0,
    ERROR = 1,
};

#if __cplusplus
}
#endif

#endif
