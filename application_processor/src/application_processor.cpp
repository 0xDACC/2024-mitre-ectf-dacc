/**
 * @file application_processor.cpp
 * @author Andrew Langan (alangan444@icloud.com)
 * @brief Application Processor Implementation
 * @version 0.1
 * @date 2024-02-20
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "board.h"
#include "i2c.h"
#include "icc.h"
#include "led.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "crc32.h"
#include "errors.h"
#include "host_messaging.h"
#include "packets.h"
#include "random.h"
#include "simple_flash.h"
#include "simple_i2c_controller.h"

#include "tinycrypt/aes.h"
#include "tinycrypt/ctr_mode.h"
#include "tinycrypt/ecc.h"
#include "tinycrypt/ecc_dh.h"
#include "tinycrypt/hmac.h"
#include "tinycrypt/sha256.h"

#ifdef POST_BOOT
#include <stdint.h>
#include <stdio.h>
#endif

// Includes from containerized build
#include "ectf_params_secure.h"
#include "global_secrets_secure.h"

using namespace i2c;

constexpr const uint32_t FLASH_ADDR =
    ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE));

constexpr const uint16_t FLASH_MAGIC = 0xDACC;

struct flash_entry_t {
    uint16_t flash_magic;
    uint32_t component_cnt;
    uint32_t component_ids[COMPONENT_CNT];
};

// Variable for information stored in flash memory
flash_entry_t flash_status;

uint8_t shared_secrets[32][COMPONENT_CNT] = {};
uint8_t private_keys[32][COMPONENT_CNT] = {};
uint8_t public_keys[64][COMPONENT_CNT] = {};
uint32_t nonces[COMPONENT_CNT] = {};

static inline uint8_t cid_to_idx(const i2c_addr_t id) {
    for (uint8_t i = 0; i < COMPONENT_CNT; ++i) {
        if (component_id_to_i2c_addr(flash_status.component_ids[i]) == id) {
            return i;
        }
    }
    return 0xFF;
}

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
int secure_send(const uint8_t address, const uint8_t *const buffer,
                const uint8_t len) {
    // TODO: Andrew, implement secure_send
    packet_t<packet_type_t::SECURE> tx_packet = {};
    tx_packet.header.magic = packet_magic_t::ENCRYPTED;
    tx_packet.payload.magic = static_cast<uint8_t>(packet_magic_t::DECRYPTED);
    tx_packet.payload.len = len;

    const uint8_t index = cid_to_idx(address);
    if (index == 0xFF) {
        return -1;
    }
    tx_packet.payload.nonce = nonces[index];
    memcpy(tx_packet.payload.data, buffer, len);
    tx_packet.header.checksum = 0;

    const packet_t<packet_type_t::SECURE> rx_packet =
        send_i2c_master_tx<packet_type_t::SECURE, packet_type_t::SECURE>(
            address, tx_packet);

    if (rx_packet.header.magic != packet_magic_t::ENCRYPTED) {
        return -1;
    } else if (rx_packet.type == packet_type_t::ERROR) {
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
int secure_receive(const i2c_addr_t address, const uint8_t *const buffer) {
    // TODO: Andrew, implement secure_receive
    packet_t<packet_type_t::SECURE> tx_packet = {};
    tx_packet.header.magic = packet_magic_t::ENCRYPTED;
    tx_packet.header.checksum = 0;

    const packet_t<packet_type_t::SECURE> rx_packet =
        send_i2c_master_tx<packet_type_t::SECURE, packet_type_t::SECURE>(
            address, tx_packet);

    if (rx_packet.header.magic != packet_magic_t::ENCRYPTED) {
        return -1;
    } else if (rx_packet.type == packet_type_t::ERROR) {
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
static int get_provisioned_ids(uint32_t *const buffer) {
    // TODO: Anybody Maybe make some changes?
    memcpy(buffer, flash_status.component_ids,
           flash_status.component_cnt * sizeof(uint32_t));
    return static_cast<int>(flash_status.component_cnt);
}

static error_t init() {

    // Enable global interrupts
    __enable_irq();

    flash_simple_init();
    random_init();

    flash_simple_read(FLASH_ADDR, &flash_status, sizeof(flash_entry_t));

    if (flash_status.flash_magic != FLASH_MAGIC) {
        print_debug("First boot, setting flash!\n");

        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.component_cnt = COMPONENT_CNT;
        memcpy(flash_status.component_ids, COMPONENT_IDS,
               COMPONENT_CNT * sizeof(uint32_t));

        if (flash_simple_write(FLASH_ADDR, &flash_status,
                               sizeof(flash_entry_t)) != error_t::SUCCESS) {
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

static error_t list_components() {
    for (uint32_t i = 0; i < flash_status.component_cnt; ++i) {
        print_info("P>0x%08lx\n", flash_status.component_ids[i]);
    }

    for (i2c_addr_t addr = 0x8; addr < 0x78; ++addr) {
        if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            continue;
        }

        packet_t<packet_type_t::LIST_COMMAND> tx_packet = {};
        tx_packet.header.magic = packet_magic_t::LIST;
        tx_packet.payload.len = 0x00;

        tx_packet.header.checksum =
            calc_checksum(&tx_packet.payload, sizeof(tx_packet.payload));

        const packet_t<packet_type_t::LIST_ACK> rx_packet =
            send_i2c_master_tx<packet_type_t::LIST_ACK,
                               packet_type_t::LIST_COMMAND>(addr, tx_packet);
        const uint32_t expected_checksum =
            calc_checksum(&rx_packet.payload, sizeof(rx_packet.payload));

        if (rx_packet.header.magic != packet_magic_t::LIST_ACK) {
            // Invalid response
            continue;
        } else if (rx_packet.header.checksum != expected_checksum) {
            // Invalid checksum
            continue;
        } else if (rx_packet.payload.len != 0x04) {
            // Invalid payload length
            continue;
        }

        uint32_t component_id = 0;
        memcpy(&component_id, rx_packet.payload.data, 0x04);
        print_info("F>0x%08lx\n", component_id);
    }
    print_success("List\n");
    return error_t::SUCCESS;
}

static error_t validate_components() {
    // This is the signing part (all systems valid on page 5)

    // TODO: Tyler, implement packet checks and signature algorithms
    for (uint32_t i = 0; i < flash_status.component_cnt; ++i) {
        /*
        // Set the I2C address of the component
        i2c_addr_t addr =
            component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Create command message
        command_message *command = (command_message *)transmit_buffer;
        command->opcode = COMPONENT_CMD_VALIDATE;

        // Send out command and receive result
        mitre_error_t result = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (result == mitre_error_t::ERROR) {
            print_error("Could not validate component\n");
            return mitre_error_t::ERROR;
        }

        const validate_message *validate = (validate_message *)receive_buffer;
        // Check that the result is correct
        if (validate->component_id != flash_status.component_ids[i]) {
            print_error("Component ID: 0x%08lx invalid\n",
                        flash_status.component_ids[i]);
            return mitre_error_t::ERROR;
        }
        */
    }
    return error_t::SUCCESS;
}

static error_t boot_components() {
    // This is the signed boot command part (Valid ACK Received? on page 5

    // TODO: Tyler, implement boot_components
    for (uint32_t i = 0; i < flash_status.component_cnt; ++i) {
        // Set the I2C address of the component
        /*
        i2c_addr_t addr =
            component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Create command message
        command_message *command = (command_message *)transmit_buffer;
        command->opcode = COMPONENT_CMD_BOOT;

        // Send out command and receive result
        mitre_error_t result = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (result == mitre_error_t::ERROR) {
            print_error("Could not boot component\n");
            return mitre_error_t::ERROR;
        }

        // Print boot message from component
        print_info("0x%08lx>%s\n", flash_status.component_ids[i],
                   receive_buffer);
                   */
    }
    return error_t::SUCCESS;
}

static error_t attest_component(const uint32_t component_id) {
    const i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    packet_t<packet_type_t::ATTEST_COMMAND> tx_packet = {};
    tx_packet.header.magic = packet_magic_t::ATTEST;
    tx_packet.payload.len = 0x06;

    memcpy(tx_packet.payload.data, "ATTEST", 0x06);

    // tx_packet.payload.sig = 0;
    // TODO: Henry and David, implement signature algorithm here

    tx_packet.header.checksum =
        calc_checksum(&tx_packet.payload, sizeof(tx_packet.payload));

    const packet_t<packet_type_t::ATTEST_ACK> rx_packet =
        send_i2c_master_tx<packet_type_t::ATTEST_ACK,
                           packet_type_t::ATTEST_COMMAND>(addr, tx_packet);
    const uint32_t expected_checksum =
        calc_checksum(&rx_packet.payload, sizeof(rx_packet.payload));

    if (rx_packet.header.magic != packet_magic_t::ATTEST_ACK) {
        // Invalid response
        print_error("Could not attest component\n");
        return error_t::ERROR;
    } else if (rx_packet.header.checksum != expected_checksum) {
        // Invalid checksum
        print_error("Could not attest component\n");
        return error_t::ERROR;
    } else if (rx_packet.payload.len != 0xC0) {
        // Invalid payload length
        print_error("Could not attest component\n");
        return error_t::ERROR;
    } else if (/*sigverify=*/false) {
        // TODO: Henry and David, implement signature verification here
        // Invalid signature
        print_error("Could not attest component\n");
        return error_t::ERROR;
    }
    uint8_t attest_loc[0x40] = {};
    uint8_t attest_date[0x40] = {};
    uint8_t attest_cust[0x40] = {};

    memcpy(attest_loc, rx_packet.payload.data, 0x40);
    memcpy(attest_date, rx_packet.payload.data + 0x40, 0x40);
    memcpy(attest_cust, rx_packet.payload.data + 0x80, 0x40);

    // TODO: Henry and David, Decrypt attest_loc, attest_date, and attest_cust

    // Print out attestation data
    print_info("C>0x%08lx\n", component_id);
    print_info("LOC>%s\nDATE>%s\nCUST>%s\n", attest_loc, attest_date,
               attest_cust);
    return error_t::SUCCESS;
}

static void perform_kex(const uint8_t addr, const uint8_t component_idx) {
    packet_t<packet_type_t::KEX> tx_packet = {};
    tx_packet.header.magic = packet_magic_t::KEX;
    tx_packet.payload.len = 0x60;

    uECC_make_key(public_keys[component_idx], private_keys[component_idx],
                  uECC_secp256r1());

    uint8_t hash[32] = {};
    TCSha256State_t sha256_ctx = {};
    tc_sha256_init(sha256_ctx);
    tc_sha256_update(sha256_ctx, public_keys[component_idx], 0x40);
    tc_sha256_final(hash, sha256_ctx);

    memcpy(tx_packet.payload.material, public_keys[component_idx], 0x40);
    memcpy(tx_packet.payload.hash, hash, 0x20);

    tx_packet.header.checksum =
        calc_checksum(&tx_packet.payload, sizeof(tx_packet.payload));

    const packet_t<packet_type_t::KEX> rx_packet =
        send_i2c_master_tx<packet_type_t::KEX, packet_type_t::KEX>(addr,
                                                                   tx_packet);
    const uint32_t expected_checksum =
        calc_checksum(&rx_packet.payload, sizeof(rx_packet.payload));
    sha256_ctx = {};
    tc_sha256_init(sha256_ctx);
    tc_sha256_update(sha256_ctx, rx_packet.payload.material, 0x40);
    tc_sha256_final(hash, sha256_ctx);

    if (rx_packet.header.magic != packet_magic_t::KEX) {
        // Invalid response
        print_error("Could not perform key exchange\n");
        return;
    } else if (rx_packet.header.checksum != expected_checksum) {
        // Invalid checksum
        print_error("Could not perform key exchange\n");
        return;
    } else if (memcmp(rx_packet.payload.hash, hash, 0x20) != 0) {
        // Invalid hash
        print_error("Could not perform key exchange\n");
        return;
    } else if (rx_packet.payload.len != 0x60) {
        // Invalid payload
        print_error("Could not perform key exchange\n");
        return;
    } else if (uECC_valid_public_key(rx_packet.payload.material,
                                     uECC_secp256r1()) != 0) {
        // Invalid public key
        print_error("Could not perform key exchange\n");
        return;
    }
    uECC_shared_secret(rx_packet.payload.material, private_keys[component_idx],
                       shared_secrets[component_idx], uECC_secp256r1());
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

static error_t validate_pin() {
    char buf[7] = {0};
    recv_input("Enter pin: ", buf, sizeof(buf));

    // TODO: Ezquiel and Cam, compare hashes, not raw strings
    if (memcmp(buf, ATTEST_HASH, 32) == 0) {
        print_debug("Pin Accepted!\n");
        return error_t::SUCCESS;
    }
    print_error("Invalid PIN!\n");
    return error_t::ERROR;
}

static error_t validate_token() {
    char buf[17] = {0};
    recv_input("Enter token: ", buf, sizeof(buf));

    // TODO: Ezquiel and Cam, compare hashes, not raw strings
    if (memcmp(buf, REPLACEMENT_HASH, 32) == 0) {
        print_debug("Token Accepted!\n");
        return error_t::SUCCESS;
    }
    print_error("Invalid Token!\n");
    return error_t::ERROR;
}

static void attempt_boot() {
    if (validate_components() != error_t::SUCCESS) {
        print_error("Components could not be validated\n");
        return;
    }
    print_debug("All Components validated\n");
    if (boot_components() != error_t::SUCCESS) {
        print_error("Failed to boot all components\n");
        return;
    }

    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");
    // Boot
    boot();
}

static void attempt_replace() {
    char buf[5] = {0};

    if (validate_token() != error_t::SUCCESS) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf, sizeof(buf));
    sscanf(buf, "%lx", &component_id_in);
    recv_input("Component ID Out: ", buf, sizeof(buf));
    sscanf(buf, "%lx", &component_id_out);

    // Find the component to swap out
    for (uint32_t i = 0; i < flash_status.component_cnt; ++i) {
        if (flash_status.component_ids[i] == component_id_out) {
            flash_status.component_ids[i] = component_id_in;

            // write updated component_ids to flash
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, &flash_status,
                               sizeof(flash_entry_t));

            // TODO: Ezquiel and Cam, implement component signatures here
            print_debug("Replaced 0x%08lx with 0x%08lx\n", component_id_out,
                        component_id_in);
            print_success("Replace\n");
            return;
        }
    }

    // Component Out was not found
    print_error("Component 0x%08lx is not provisioned for the system\r\n",
                component_id_out);
}

static void attempt_attest() {
    char buf[5] = {0};

    if (validate_pin() != error_t::SUCCESS) {
        return;
    }
    uint32_t component_id = 0;
    recv_input("Component ID: ", buf, sizeof(buf));
    sscanf(buf, "%lx", &component_id);
    if (attest_component(component_id) == error_t::SUCCESS) {
        print_success("Attest\n");
    }
}

int main() {
    if (init() != error_t::SUCCESS) {
        print_error("Failed to initialize board\n");
        return -1;
    }

    print_info("Application Processor Started\n");

    // Handle commands forever
    char buf[8] = {0};
    while (true) {
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
