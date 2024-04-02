/**
 * @file component.h
 * @author Andrew Langan (alangan444@icloud.com
 * @brief Types and function signatures for the component
 * @version 0.1
 * @date 2024-03-07
 *
 * @copyright Copyright (c) 2024
 *
 */
#ifndef COMPONENT
#define COMPONENT

#include "errors.h"
#include <stdint.h>

enum class state_t { PREBOOT, POSTBOST };

/**
 * @brief Process command sent to the component
 *
 * @param data Data received from the I2C ISR
 * @return Whether the command was processed successfully
 */
error_t component_process_cmd(const uint8_t *const data);

/**
 * @brief Process the attest command
 *
 * @param data Data received from the I2C ISR
 * @return Whether the command was processed successfully
 */
error_t process_attest(const uint8_t *const data);

/**
 * @brief Process the boot command
 *
 * @param data Data received from the I2C ISR
 * @return Whether the command was processed successfully
 */
error_t process_boot(const uint8_t *const data);

/**
 * @brief Process the ecc key exchange command
 *
 * @param data Data received from the I2C ISR
 * @return Whether the command was processed successfully
 */
error_t process_kex(const uint8_t *const data);

/**
 * @brief Process the list command
 *
 * @param data Data received from the I2C ISR
 * @return Whether the command was processed successfully
 */
error_t process_list(const uint8_t *const data);

/**
 * @brief Process the replace command
 *
 * @param data Data received from the I2C ISR
 * @return Whether the command was processed successfully
 */
error_t process_replace(const uint8_t *const data);

/**
 * @brief Process the boot signature command
 *
 * @param data Data received from the I2C ISR
 * @return Whether the command was processed successfully
 */
error_t process_boot_sig(const uint8_t *const data);

/**
 * @brief Secure Send
 *
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent
 *
 * Securely send data over I2C. This function is utilized in POST_BOOT
 * functionality. This function must be implemented by your team to align with
 * the security requirements.
 */
void secure_send(const uint8_t *const buffer, const uint8_t len);

/**
 * @brief Secure Receive
 *
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 *
 * @return int: number of bytes received, negative if error
 *
 * Securely receive data over I2C. This function is utilized in POST_BOOT
 * functionality. This function must be implemented by your team to align
 * with the security requirements.
 */
int secure_receive(uint8_t *const buffer);

#endif /* COMPONENT */
