import secrets

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR

input_component = open("inc/ectf_params.h", "rt", encoding="utf-8")
output = open("inc/ectf_params_secure.h", "wt", encoding="utf-8")
output.write(
    """
#include <stdint.h>
#pragma once
"""
)


def wrap_key(key: bytes, nonce: bytes, wrapper: bytes) -> bytes:
    """Wrap a key with a wrapper key

    Args:
        key (bytes): Key to wrap
        nonce (bytes): Nonce for the AES-CTR cipher
        wrapper (bytes): Wrapper key

    Returns:
        bytes: Wrapped key
    """
    cipher = Cipher(
        AES(wrapper), mode=CTR(nonce), backend=default_backend()
    ).encryptor()
    return cipher.update(key) + cipher.finalize()


def parse_global_attest() -> tuple[bytes, bytes]:
    """Parse the global attestation key and nonce from the deployment secrets

    Returns:
        tuple[bytes, bytes]: The attestation key and nonce
    """
    lines: list[str] = open(
        "../deployment/global_secrets_secure.h", "rt", encoding="utf-8"
    ).readlines()
    attest_nonce: bytes = b""
    attest_key_unwrapped: bytes = b""
    for line in lines:
        if "ATTEST_NONCE_UNWRAPPED" in line:
            attest_nonce = bytes.fromhex(line.split(" ")[2].strip(' \n"'))
        elif "ATTEST_KEY_UNWRAPPED" in line:
            attest_key_unwrapped = bytes.fromhex(line.split(" ")[2].strip(' \n"'))
    if not attest_nonce or not attest_key_unwrapped:
        raise ValueError("Missing attestation encryption parameters")
    return attest_key_unwrapped, attest_nonce


def encrypt_attestation(
    loc: str, date: str, cust: str, nonce: bytes, key: bytes
) -> tuple[bytes, bytes, bytes]:
    """Encrypt the attestation parameters

    Args:
        loc (str): Attestation location
        date (str): Attestation date
        cust (str): Attestation customer
        nonce (bytes): Nonce for the AES-CTR cipher
        key (bytes): Key for the AES-CTR cipher

    Returns:
        tuple[bytes, bytes, bytes]: Encrypted attestation parameters
    """
    cipher = Cipher(AES(key), mode=CTR(nonce), backend=default_backend()).encryptor()
    return (
        cipher.update(loc.encode()),
        cipher.update(date.encode()),
        cipher.update(cust.encode()) + cipher.finalize(),
    )


def write(type: str, name: str, values: list[str]) -> None:
    """Write a constant to the ectf_params.h file

    Args:
        type (str): Type of the constant
        name (str): Variable name
        values (list[str]): Value of the constant
    """
    if "[" in type and "]" in type:
        output.write(f"constexpr const {type.split('[')[0]} {name}[{len(values)}] = {{")
        for value in values:
            output.write(f"{value},")
        output.write("};\n")
    else:
        output.write(f"constexpr const {type} {name} = {values[0]};\n")


def parse_component_attestation() -> tuple[str, str, str, str, str]:
    """Parse the component parameters from the ectf_params.h file

    Raises:
        ValueError: If any of the attestation parameters are missing

    Returns:
        tuple[str, str, str]:  The attestation parameters
    """
    lines: list[str] = input_component.readlines()
    attest_loc: str = ""
    attest_date: str = ""
    attest_cust: str = ""
    component_id: str = ""
    component_boot_msg: str = ""
    for line in lines:
        if "ATTESTATION_LOC" in line:
            attest_loc = line.split(" ")[2].strip(' \n"')
        elif "ATTESTATION_DATE" in line:
            attest_date = line.split(" ")[2].strip(' \n"')
        elif "ATTESTATION_CUSTOMER" in line:
            attest_cust = line.split(" ")[2].strip(' \n"')
        elif "COMPONENT_ID" in line:
            component_id = line.split(" ")[2].strip(' \n"')
        elif "COMPONENT_BOOT_MSG" in line:
            component_boot_msg = line.split(" ")[2].strip(' \n"')
    if (
        not attest_loc
        or not attest_date
        or not attest_cust
        or not component_id
        or not component_boot_msg
    ):
        raise ValueError("Missing attestation parameters")
    for _ in range(64 - len(attest_loc)):
        attest_loc += "\x00"
    for _ in range(64 - len(attest_date)):
        attest_date += "\x00"
    for _ in range(64 - len(attest_cust)):
        attest_cust += "\x00"
    for _ in range(64 - len(component_boot_msg)):
        component_boot_msg += "\x00"
    return attest_loc, attest_date, attest_cust, component_id, component_boot_msg


attest_loc, attest_date, attest_cust, component_id, component_boot_msg = (
    parse_component_attestation()
)
attest_key, attest_nonce = parse_global_attest()
attest_loc, attest_date, attest_cust = encrypt_attestation(
    attest_loc,
    attest_date,
    attest_cust,
    attest_nonce,
    attest_key,
)

write("uint8_t[]", "ATTEST_KEY", [f"{b}" for b in attest_key])
write("uint8_t[]", "ATTEST_NONCE", [f"{b}" for b in attest_nonce])
write("uint8_t[]", "ATTEST_LOC_ENC", [f"{b}" for b in attest_loc])
write("uint8_t[]", "ATTEST_DATE_ENC", [f"{b}" for b in attest_date])
write("uint8_t[]", "ATTEST_CUST_ENC", [f"{b}" for b in attest_cust])
write("uint8_t[]", "COMPONENT_BOOT_MSG", [f"{b}" for b in component_boot_msg.encode()])
write("uint32_t", "COMPONENT_ID", [component_id])


attest_loc = attest_loc.hex()
attest_date = attest_date.hex()
attest_cust = attest_cust.hex()
attest_key = attest_key.hex()
attest_nonce = attest_nonce.hex()

input_component.close()
output.close()
