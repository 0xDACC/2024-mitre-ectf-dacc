/**
 * @file application_processor.c
 * @author Jacob Doll
 * @brief eCTF AP Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2024 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "board.h"
#include "i2c.h"
#include "icc.h"
#include "led.h"

#include "mxc_delay.h"
#include "mxc_device.h"
#include "nvic_table.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "errors.h"
#include "host_messaging.h"
#include "simple_flash.h"
#include "simple_i2c_controller.h"

#ifdef POST_BOOT
#include <stdint.h>
#include <stdio.h>
#endif

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets_secure.h"

using namespace i2c;

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define AP_PIN "123456"
#define AP_TOKEN "0123456789abcdef"
#define COMPONENT_IDS 0x11111124, 0x11111125
#define COMPONENT_CNT 2
#define AP_BOOT_MSG "Test boot message"
*/

static inline void unwrap(uint8_t *key, uint8_t *wrapper, uint8_t len) {
    for (uint8_t i = 0; i < len) {
        key[i] ^= wrapper[i];
    }
}

// Flash Macros
#define FLASH_ADDR                                                             \
    ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Datatype for information stored in flash
typedef struct {
    uint32_t flash_magic;
    uint32_t component_cnt;
    uint32_t component_ids[32];
} flash_entry;

// Variable for information stored in flash memory
flash_entry flash_status;

/**
 * @brief Secure Send
 *
 * @param address: i2c_addr_t, I2C address of recipient
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent
 *
 * Securely send data over I2C. This function is utilized in POST_BOOT
 functionality.
 * This function must be implemented by your team to align with the security
 requirements.

*/
int secure_send(uint8_t address, uint8_t *buffer, uint8_t len) {
    packet_t<packet_type_t::SECURE> packet;
    packet.header.magic = packet_magic_t::ENCRYPTED;
    packet.header.checksum = 0;

    const auto response = send_i2c_tx<packet_type_t::SECURE>(address, packet);

    if (response.header.magic != packet_magic_t::ENCRYPTED) {
        return -1;
    } else if (response.type == packet_type_t::ERROR) {
        return -1;
    } else {
        return 0;
    }
}

/**
 * @brief Secure Receive
 *
 * @param address: i2c_addr_t, I2C address of sender
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 *
 * @return int: number of bytes received, negative if error
 *
 * Securely receive data over I2C. This function is utilized in POST_BOOT
 * functionality. This function must be implemented by your team to align with
 * the security requirements.
 */
int secure_receive(i2c_addr_t address, uint8_t *buffer) {
    packet_t<packet_type_t::SECURE> packet;
    packet.header.magic = packet_magic_t::ENCRYPTED;
    packet.header.checksum = 0;

    const auto response = send_i2c_tx<packet_type_t::SECURE>(address, packet);

    if (response.header.magic != packet_magic_t::ENCRYPTED) {
        return -1;
    } else if (response.type == packet_type_t::ERROR) {
        return -1;
    } else {
        return 0;
    }
}

/**
 * @brief Get Provisioned IDs
 *
 * @param uint32_t* buffer
 *
 * @return int: number of ids
 *
 * Return the currently provisioned IDs and the number of provisioned IDs
 * for the current AP. This functionality is utilized in POST_BOOT
 * functionality. This function must be implemented by your team.
 */
int get_provisioned_ids(uint32_t *const buffer) {
    memcpy(buffer, flash_status.component_ids,
           flash_status.component_cnt * sizeof(uint32_t));
    return flash_status.component_cnt;
}

// Initialize the device
// This must be called on startup to initialize the flash and i2c interfaces
error_t init() {

    // Enable global interrupts
    __enable_irq();

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_simple_read(FLASH_ADDR, reinterpret_cast<uint32_t *>(&flash_status),
                      sizeof(flash_entry));

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
        print_debug("First boot, setting flash!\n");

        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.component_cnt = COMPONENT_CNT;
        const uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
        memcpy(flash_status.component_ids, component_ids,
               COMPONENT_CNT * sizeof(uint32_t));

        if (flash_simple_write(FLASH_ADDR,
                               reinterpret_cast<uint32_t *>(&flash_status),
                               sizeof(flash_entry)) < 0) {
            print_error("Failed to write to flash\n");
            return error_t::ERROR;
        }
    }

    if (i2c_simple_controller_init() != error_t::SUCCESS) {
        print_error("Failed to initialize I2C\n");
        return error_t::ERROR;
    }
    return error_t::SUCCESS;
}

error_t list_components(void) {
    // Print out provisioned component IDs
    for (unsigned i = 0; i < flash_status.component_cnt; ++i) {
        print_info("P>0x%08x\n", flash_status.component_ids[i]);
    }

    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN] = {0};
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN] = {0};

    for (i2c_addr_t addr = 0x8; addr < 0x78; addr++) {
        // I2C Blacklist:
        // 0x18, 0x28, and 0x36 conflict with separate devices on MAX78000FTHR
        if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            continue;
        }

        // Create command message
        command_message *command = (command_message *)transmit_buffer;
        command->opcode = COMPONENT_CMD_SCAN;

        // Send out command and receive result
        error_t result = issue_cmd(addr, transmit_buffer, receive_buffer);

        // Success, device is present
        if (result == error_t::SUCCESS) {
            const scan_message *scan = (scan_message *)receive_buffer;
            print_info("F>0x%08x\n", scan->component_id);
        }
    }
    print_success("List\n");
    return error_t::SUCCESS;
}

error_t validate_components(void) {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN] = {0};
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN] = {0};

    // Send validate command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; ++i) {
        // Set the I2C address of the component
        i2c_addr_t addr =
            component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Create command message
        command_message *command = (command_message *)transmit_buffer;
        command->opcode = COMPONENT_CMD_VALIDATE;

        // Send out command and receive result
        error_t result = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (result == error_t::ERROR) {
            print_error("Could not validate component\n");
            return error_t::ERROR;
        }

        const validate_message *validate = (validate_message *)receive_buffer;
        // Check that the result is correct
        if (validate->component_id != flash_status.component_ids[i]) {
            print_error("Component ID: 0x%08x invalid\n",
                        flash_status.component_ids[i]);
            return error_t::ERROR;
        }
    }
    return error_t::SUCCESS;
}

error_t boot_components(void) {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN] = {0};
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN] = {0};

    // Send boot command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; ++i) {
        // Set the I2C address of the component
        i2c_addr_t addr =
            component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Create command message
        command_message *command = (command_message *)transmit_buffer;
        command->opcode = COMPONENT_CMD_BOOT;

        // Send out command and receive result
        error_t result = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (result == error_t::ERROR) {
            print_error("Could not boot component\n");
            return error_t::ERROR;
        }

        // Print boot message from component
        print_info("0x%08x>%s\n", flash_status.component_ids[i], receive_buffer);
    }
    return error_t::SUCCESS;
}

error_t attest_component(uint32_t component_id) {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN] = {0};
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN] = {0};

    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    // Create command message
    command_message *command = (command_message *)transmit_buffer;
    command->opcode = COMPONENT_CMD_ATTEST;

    // Send out command and receive result
    error_t result = issue_cmd(addr, transmit_buffer, receive_buffer);
    if (result == error_t::ERROR) {
        print_error("Could not attest component\n");
        return error_t::ERROR;
    }

    // Print out attestation data
    print_info("C>0x%08x\n", component_id);
    print_info("%s", receive_buffer);
    return error_t::SUCCESS;
}

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot() {

// POST BOOT FUNCTIONALITY
// DO NOT REMOVE IN YOUR DESIGN
#ifdef POST_BOOT
    POST_BOOT
#else
    // Everything after this point is modifiable in your design
    // LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
#endif
}

// Compare the entered PIN to the correct PIN
error_t validate_pin(void) {
    char buf[7] = {0};
    recv_input("Enter pin: ", buf, sizeof(buf));
    if (strcmp(buf, AP_PIN) == 0) {
        print_debug("Pin Accepted!\n");
        return error_t::SUCCESS;
    }
    print_error("Invalid PIN!\n");
    return error_t::ERROR;
}

// Function to validate the replacement token
error_t validate_token(void) {
    char buf[17] = {0};
    recv_input("Enter token: ", buf, sizeof(buf));
    if (strcmp(buf, AP_TOKEN) == 0) {
        print_debug("Token Accepted!\n");
        return error_t::SUCCESS;
    }
    print_error("Invalid Token!\n");
    return error_t::ERROR;
}

// Boot the components and board if the components validate
void attempt_boot(void) {
    if (validate_components() != error_t::SUCCESS) {
        print_error("Components could not be validated\n");
        return;
    }
    print_debug("All Components validated\n");
    if (boot_components() != error_t::SUCCESS) {
        print_error("Failed to boot all components\n");
        return;
    }
    // Print boot message
    // This always needs to be printed when booting
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");
    // Boot
    boot();
}

// Replace a component if the PIN is correct
void attempt_replace(void) {
    char buf[5] = {0};

    if (validate_token() != error_t::SUCCESS) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf, sizeof(buf));
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf, sizeof(buf));
    sscanf(buf, "%x", &component_id_out);

    // Find the component to swap out
    for (unsigned i = 0; i < flash_status.component_cnt; ++i) {
        if (flash_status.component_ids[i] == component_id_out) {
            flash_status.component_ids[i] = component_id_in;

            // write updated component_ids to flash
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t *)&flash_status,
                               sizeof(flash_entry));

            print_debug("Replaced 0x%08x with 0x%08x\n", component_id_out,
                        component_id_in);
            print_success("Replace\n");
            return;
        }
    }

    // Component Out was not found
    print_error("Component 0x%08x is not provisioned for the system\r\n",
                component_id_out);
}

// Attest a component if the PIN is correct
void attempt_attest(void) {
    char buf[5] = {0};

    if (validate_pin() != error_t::SUCCESS) {
        return;
    }
    uint32_t component_id = 0;
    recv_input("Component ID: ", buf, sizeof(buf));
    sscanf(buf, "%x", &component_id);
    if (attest_component(component_id) == error_t::SUCCESS) {
        print_success("Attest\n");
    }
}

int main(void) {
    // Initialize board
    if (init() != error_t::SUCCESS) {
        print_error("Failed to initialize board\n");
        return -1;
    }

    // Print the component IDs to be helpful
    // Your design does not need to do this
    print_info("Application Processor Started\n");

    // Handle commands forever
    char buf[8] = {0};
    while (1) {
        recv_input("Enter Command: ", buf, sizeof(buf));

        // Execute requested command
        if (strcmp(buf, "list") == 0) {
            list_components();
        } else if (strcmp(buf, "boot") == 0) {
            attempt_boot();
        } else if (strcmp(buf, "replace") == 0) {
            attempt_replace();
        } else if (strcmp(buf, "attest") == 0) {
            attempt_attest();
        } else {
            print_error("Unrecognized command '%s'\n", buf);
        }
    }

    // Code never reaches here
    return 0;
}
