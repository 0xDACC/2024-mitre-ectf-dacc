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

#ifndef HOST_MESSAGING
#define HOST_MESSAGING

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/**
 * @brief Receives a message from the host over UART
 *
 * @param msg The message to display to the user
 * @param buf The buffer to store the message in
 * @param buflen The length of the buffer
 */
void recv_input(const char *msg, char *buf, size_t buflen);

/**
 * @brief Receives a message from the host over UART
 *
 * @param msg The message to display to the user
 * @param buf The buffer to store the message in
 * @param buflen The length of the buffer
 */
void recv_input(const char *msg, uint8_t *buf, size_t buflen);

/**
 * @brief Prints a buffer of bytes as a hex string
 *
 * @param buf Buffer to print
 * @param len Length of the buffer
 */
void print_hex(const uint8_t *buf, size_t len);

/**
 * @brief Defines a function as being printf-like
 *
 */
#define PF __attribute__((format(printf, 1, 2)))

/**
 * @brief Prints an error message
 *
 */
static inline void PF print_error(const char *fmt, ...) {
    printf("%%error: ");
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("%%");
    fflush(stdout);
}

/**
 * @brief Prints an error as a hex string
 *
 * @param buf Buffer to print
 * @param len Length of the buffer
 */
static inline void print_hex_error(const uint8_t *const buf, const size_t len) {
    printf("%%error: ");
    print_hex(buf, len);
    printf("%%");
    fflush(stdout);
}

/**
 * @brief Prints a success message
 *
 */
static inline void PF print_success(const char *fmt, ...) {
    printf("%%success: ");
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("%%");
    fflush(stdout);
}

/**
 * @brief Prints a success message as a hex string
 *
 * @param buf Buffer to print
 * @param len Length of the buffer
 */
static inline void print_hex_success(const uint8_t *const buf,
                                     const size_t len) {
    printf("%%success: ");
    print_hex(buf, len);
    printf("%%");
    fflush(stdout);
}

/**
 * @brief Prints a debug message
 *
 */
static inline void PF print_debug(const char *fmt, ...) {
    printf("%%debug: ");
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("%%");
    fflush(stdout);
}

/**
 * @brief Prints a debug message as a hex string
 *
 * @param buf Buffer to print
 * @param len Length of the buffer
 */
static inline void print_hex_debug(const uint8_t *const buf, const size_t len) {
    printf("%%debug: ");
    print_hex(buf, len);
    printf("%%");
    fflush(stdout);
}

/**
 * @brief Prints an info message
 *
 */
static inline void PF print_info(const char *fmt, ...) {
    printf("%%info: ");
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("%%");
    fflush(stdout);
}

/**
 * @brief Prints an info message as a hex string
 *
 * @param buf Buffer to print
 * @param len Length of the buffer
 */
static inline void print_hex_info(const uint8_t *const buf, const size_t len) {
    printf("%%info: ");
    print_hex(buf, len);
    printf("%%");
    fflush(stdout);
}

/**
 * @brief Prints an acknowledgement message
 *
 */
static inline void print_ack() {
    printf("%%ack%%\n");
    fflush(stdout);
}

#undef PF

#endif
