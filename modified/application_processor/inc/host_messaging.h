/**
 * @file host_messaging.h
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief Safer messaging between host and application processor
 * @version 0.1
 * @date 2024-01-31
 *
 * @copyright Copyright (c) 2024
 *
 */

#ifndef __HOST_MESSAGING__
#define __HOST_MESSAGING__

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Print a message through USB UART and then receive a line over USB UART
void recv_input(const char *msg, char *buf, size_t buflen);

// Prints a buffer of bytes as a hex string
void print_hex(const uint8_t *buf, size_t len);

#define PF __attribute__((format(printf, 1, 2)))

static inline void PF print_error(const char *fmt, ...) {
    printf("%%error: ");
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("%%");
    fflush(stdout);
}

static inline void print_hex_error(const uint8_t *const buf, const size_t len) {
    printf("%%error: ");
    print_hex(buf, len);
    printf("%%");
    fflush(stdout);
}

static inline void PF print_success(const char *fmt, ...) {
    printf("%%success: ");
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("%%");
    fflush(stdout);
}

static inline void print_hex_success(const uint8_t *const buf,
                                     const size_t len) {
    printf("%%success: ");
    print_hex(buf, len);
    printf("%%");
    fflush(stdout);
}

static inline void PF print_debug(const char *fmt, ...) {
    printf("%%debug: ");
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("%%");
    fflush(stdout);
}

static inline void print_hex_debug(const uint8_t *const buf, const size_t len) {
    printf("%%debug: ");
    print_hex(buf, len);
    printf("%%");
    fflush(stdout);
}

static inline void PF print_info(const char *fmt, ...) {
    printf("%%info: ");
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("%%");
    fflush(stdout);
}

static inline void print_hex_info(const uint8_t *const buf, const size_t len) {
    printf("%%info: ");
    print_hex(buf, len);
    printf("%%");
    fflush(stdout);
}

static inline void print_ack() {
    printf("%%ack%%\n");
    fflush(stdout);
}

#undef PF

#endif
