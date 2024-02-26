/**
 * @file component.cpp
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief Main component file
 * @version 0.1
 * @date 2024-02-22
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "board.h"
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "errors.h"
#include "packets.h"
#include "simple_i2c_peripheral.h"

// Includes from containerized build
#include "ectf_params_secure.h"
#include "global_secrets_secure.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

// Core function definitions
static mitre_error_t component_process_cmd(const uint8_t *const data,
                                           const uint32_t len);
static void process_boot(const uint8_t *const data, const uint32_t len);
static void process_list(const uint8_t *const data, const uint32_t len);
static void process_validate(const uint8_t *const data, const uint32_t len);
static void process_attest(const uint8_t *const data, const uint32_t len);
enum class state_t { PREBOOT, POSTBOST };
static volatile state_t state = state_t::PREBOOT;

using namespace i2c;

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
static void secure_send(const uint8_t *const buffer, const uint8_t len) {
    // TODO: Andrew, implement secure_send
    packet_t<packet_type_t::SECURE> tx_packet;
    tx_packet.header.magic = packet_magic_t::ENCRYPTED;
    tx_packet.header.checksum = 0;

    const packet_t<packet_type_t::SECURE> rx_packet =
        send_i2c_slave_tx<packet_type_t::SECURE, packet_type_t::SECURE>(
            tx_packet);

    if (rx_packet.header.magic != packet_magic_t::ENCRYPTED) {
    } else if (rx_packet.type == packet_type_t::ERROR) {
    } else {
    }
}
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
static int secure_receive(const uint8_t *const buffer) {
    // TODO: Andrew, implement secure_send
    packet_t<packet_type_t::SECURE> tx_packet;
    tx_packet.header.magic = packet_magic_t::ENCRYPTED;
    tx_packet.header.checksum = 0;

    const packet_t<packet_type_t::SECURE> rx_packet =
        send_i2c_slave_tx<packet_type_t::SECURE, packet_type_t::SECURE>(
            tx_packet);

    if (rx_packet.header.magic != packet_magic_t::ENCRYPTED) {
        return -1;
    } else if (rx_packet.type == packet_type_t::ERROR) {
        return -1;
    } else {
        return 0;
    }
}

// Example boot sequence
// Your design does not need to change this
static void boot() {

// POST BOOT FUNCTIONALITY
// DO NOT REMOVE IN YOUR DESIGN
#ifdef POST_BOOT
    POST_BOOT
#else
    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
    // LED loop to show that boot occurred
    while (true) {
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

// Handle a transaction from the AP
static mitre_error_t component_process_cmd(const uint8_t *const data,
                                           const uint32_t len) {
    if (data == nullptr || len < 5) {
        return mitre_error_t::ERROR;
    }
    switch (static_cast<packet_magic_t>(data[0])) {
    case packet_magic_t::ATTEST:
        process_attest(data, len);
        break;
    case packet_magic_t::BOOT:
        process_boot(data, len);
        break;
    case packet_magic_t::KEX_P1:
        // Do KEX
        break;
    case packet_magic_t::LIST:
        process_list(data, len);
        break;
    default:
        printf("Error: Unrecognized command received %d\n", data[0]);
        return mitre_error_t::ERROR;
    }
    return mitre_error_t::SUCCESS;
}

static void process_boot(const uint8_t *const data, const uint32_t len) {
    if (len < 75) {
        // Invalid packet length
        return;
    }

    packet_t<packet_type_t::BOOT_COMMAND> rx_packet;
    rx_packet.header.magic = packet_magic_t::LIST;
    rx_packet.header.checksum = *reinterpret_cast<const uint32_t *>(&data[1]);

    memcpy(&rx_packet.payload, &data[5], len - 5);

    if (rx_packet.header.checksum != 0) {
        // TODO: Andrew, add checksum
        // Checksum failed
        return;
    } else if (rx_packet.payload.len != 0x04) {
        // Invalid payload length
        return;
    } else if (memcmp(rx_packet.payload.data, "BOOT", 0x4) != 0) {
        // Invalid payload
        return;
    } else if (/*sigverify(data) ==*/false) {
        // TODO: Tyler, implement signature verification here
        // Invalid signature
        return;
    }

    packet_t<packet_type_t::BOOT_ACK> tx_packet;
    tx_packet.header.magic = packet_magic_t::BOOT_ACK;
    // TODO: Andrew, Add checksum
    tx_packet.header.checksum = 0;
    tx_packet.payload.len = 0x40;

    memcpy(tx_packet.payload.data, COMPONENT_BOOT_MSG, 0x40);

    // tx_packet.payload.sig = 0;
    // TODO: Tyler, implement signature algorithm here

    handler->send_packet<packet_type_t::BOOT_ACK>(tx_packet);
    state = state_t::POSTBOST;
}

static void process_list(const uint8_t *const data, const uint32_t len) {
    if (len < 6) {
        // Invalid packet length
        return;
    }

    packet_t<packet_type_t::LIST_COMMAND> rx_packet;
    rx_packet.header.magic = packet_magic_t::LIST;

    memcpy(&rx_packet.header.checksum, &data[1], 0x04);
    memcpy(&rx_packet.payload, &data[5], len - 5);

    if (rx_packet.header.checksum != 0) {
        // TODO: Andrew, add checksum
        // Checksum failed
        return;
    } else if (rx_packet.payload.len != 0x00) {
        // Invalid payload length
        return;
    }

    packet_t<packet_type_t::LIST_ACK> tx_packet;
    tx_packet.header.magic = packet_magic_t::LIST_ACK;
    // TODO: Andrew, add checksum
    tx_packet.header.checksum = 0;
    tx_packet.payload.len = 0x04;

    memcpy(tx_packet.payload.data, &COMPONENT_ID, 0x04);

    handler->send_packet<packet_type_t::LIST_ACK>(tx_packet);
}

static void process_validate(const uint8_t *const data, const uint32_t len) {
    // This is the signing part (all systems valid on page 5)

    // TODO: Tyler, implement packet checks and signature algorithms
    return;
}

static void process_attest(const uint8_t *const data, const uint32_t len) {
    if (len < 77) {
        // Invalid packet length
        return;
    }

    packet_t<packet_type_t::ATTEST_COMMAND> rx_packet;
    rx_packet.header.magic = packet_magic_t::ATTEST;
    rx_packet.header.checksum = *reinterpret_cast<const uint32_t *>(&data[1]);

    memcpy(&rx_packet.payload, &data[5], len - 5);

    if (rx_packet.header.checksum != 0) {
        // TODO: Andrew, add checksum
        // Checksum failed
        return;
    } else if (rx_packet.payload.len != 0x6) {
        // Invalid payload length
        return;
    } else if (memcmp(rx_packet.payload.data, "ATTEST", 0x6) != 0) {
        // Invalid payload
        return;
    } else if (/*sigverify(data) ==*/false) {
        // TODO: Henry and David, implement signature verification here
        // Invalid signature
        return;
    }

    packet_t<packet_type_t::ATTEST_ACK> tx_packet;
    tx_packet.header.magic = packet_magic_t::ATTEST_ACK;
    // TODO: Andrew Add checksum
    tx_packet.header.checksum = 0;
    tx_packet.payload.len = 0xC0;

    memcpy(tx_packet.payload.data, ATTEST_LOC_ENC, 0x40);
    memcpy(tx_packet.payload.data + 0x40, ATTEST_DATE_ENC, 0x40);
    memcpy(tx_packet.payload.data + 0x80, ATTEST_CUST_ENC, 0x40);

    // tx_packet.payload.sig = 0;
    // TODO: Henry and David, implement signature algorithm here

    handler->send_packet<packet_type_t::ATTEST_ACK>(tx_packet);
}

int main() {
    printf("Component Started\n");

    // Enable Global Interrupts
    __enable_irq();

    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    if (i2c_simple_peripheral_init(addr, component_process_cmd) !=
        mitre_error_t::SUCCESS) {
        printf("Failed to initialize I2C peripheral.\n");
        return -1;
    }

    LED_On(LED2);

    while (true) {
        // Do nothing
        if (state == state_t::POSTBOST) {
            // TODO: Disable all functions
            boot();
        }
    }
}
