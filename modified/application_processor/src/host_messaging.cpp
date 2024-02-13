/**
 * @file host_messaging.cpp
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief Safer host messaging functions
 * @version 0.1
 * @date 2024-01-31
 *
 * @copyright Copyright (c) 2024
 *
 */
#include "host_messaging.h"
#include <string.h>

// Print a message through USB UART and then receive a line over USB UART
void recv_input(const char *const msg, char *const buf, const size_t buflen) {
    print_debug("%s", msg);
    fflush(nullptr);
    print_ack();
    size_t i = 0;
    int ch = 0;
    do {
        ch = getchar();
        buf[i] = ch;
        ++i;
    } while (ch != '\n' && i < buflen - 1);
    buf[i - 1] = '\0';
    printf("\n");
}
// Prints a buffer of bytes as a hex string
void print_hex(const uint8_t *const buf, const size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}
