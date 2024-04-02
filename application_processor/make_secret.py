import secrets

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.hashes import Hash, SHA256

input_ap = open("inc/ectf_params.h", "rt", encoding="utf-8")
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


def hash_pin(pin: int, iterations: int) -> bytes:
    """Hashes the attestation pin

    Args:
        pin (int): Attestation pin
        iterations (int): Number of iterations

    Returns:
        bytes: Hashed pin
    """
    hasher = Hash(SHA256(), backend=default_backend())
    for _ in range(iterations):
        hasher.update(hex(pin)[2::].encode("utf-8"))
    return hasher.finalize()


def hash_replacement(token: int) -> bytes:
    """Hashes the replacement token

    Args:
        token (int): Replacement token

    Returns:
        bytes: Hashed token
    """
    hasher = Hash(SHA256(), backend=default_backend())
    hasher.update(hex(token)[2::].encode("utf-8"))
    return hasher.finalize()


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


def parse_ap_params() -> tuple[int, int, list[str], str]:
    """Reads the AP parameters from the ectf_params.h file

    Raises:
        ValueError: If an AP parameter is missing

    Returns:
        tuple[int, int]: The attestation pin and replacement token
    """
    lines: list[str] = input_ap.readlines()
    attest_pin: int = 0x0
    replacement_token: int = 0x0
    component_ids: list[str] = []
    boot_msg: str = ""
    for line in lines:
        if "AP_PIN" in line:
            attest_pin = int(line.split(" ")[2].strip(' \n"'), 16)
        elif "AP_TOKEN" in line:
            replacement_token = int(line.split(" ")[2].strip(' \n"'), 16)
        elif "COMPONENT_IDS" in line:
            component_ids = "".join(line.split(" ")[2::]).strip(' \n"').split(",")
        elif "AP_BOOT_MSG" in line:
            boot_msg = line.split(" ")[2].strip(' \n"')
    if not attest_pin or not replacement_token or not component_ids or not boot_msg:
        raise ValueError("Missing AP parameters")
    return attest_pin, replacement_token, component_ids, boot_msg


ITERATIONS: int = 25000
attest_pin, replacement_token, component_ids, boot_msg = parse_ap_params()
attest_pin_hash = hash_pin(attest_pin, ITERATIONS)
write("uint8_t[]", "ATTEST_HASH", [f"{b}" for b in attest_pin_hash])

replacement_token = hash_replacement(replacement_token)

attest_nonce = secrets.token_bytes(16)
attest_key_unwrapped, _ = parse_global_attest()


attest_pin = hash_pin(attest_pin, ITERATIONS - 1)
attest_key_wrapped = wrap_key(attest_key_unwrapped, attest_nonce, attest_pin[:16])

write("uint8_t[]", "REPLACEMENT_HASH", [f"{b}" for b in replacement_token])
write("char *const", "AP_BOOT_MSG", [f'"{boot_msg}"'])
write("uint32_t[]", "COMPONENT_IDS", [f"{id}" for id in component_ids])
write("uint32_t", "COMPONENT_CNT", [f"{len(component_ids)}"])
write("uint32_t", "ITERATIONS", [f"{ITERATIONS}"])
write("uint8_t[]", "ATTEST_WRAPPER_NONCE", [f"{b}" for b in attest_nonce])
write("uint8_t[]", "ATTEST_KEY_WRAPPED", [f"{b}" for b in attest_key_wrapped])

attest_pin = attest_pin.hex()
replacement_token = replacement_token.hex()

input_ap.close()
output.close()
