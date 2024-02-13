from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.hashes import Hash, SHA256

input_ap = open("inc/ectf_params.h", "rt", encoding="utf-8")
output = open("inc/ectf_params_secure.h", "wt", encoding="utf-8")
output.write("""
#include <stdint.h>
#pragma once
""")


def wrap_key(key: bytes, nonce: bytes, wrapper: bytes) -> bytes:
    """Wrap a key with a wrapper key

    Args:
        key (bytes): Key to wrap
        nonce (bytes): Nonce for the AES-CTR cipher
        wrapper (bytes): Wrapper key

    Returns:
        bytes: Wrapped key
    """
    cipher = Cipher(AES(key), mode=CTR(nonce),
                    backend=default_backend()).encryptor()
    return cipher.update(wrapper) + cipher.finalize()


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
        hasher.update(pin.to_bytes(6, "big"))
    return hasher.finalize()


def hash_replacement(token: int) -> bytes:
    """Hashes the replacement token

    Args:
        token (int): Replacement token

    Returns:
        bytes: Hashed token
    """
    hasher = Hash(SHA256(), backend=default_backend())
    hasher.update(token.to_bytes(16, "big"))
    return hasher.finalize()


def write(type: str, name: str, values: list[str]) -> None:
    """Write a constant to the ectf_params.h file

    Args:
        type (str): Type of the constant
        name (str): Variable name
        values (list[str]): Value of the constant
    """
    if "[" in type and "]" in type:
        output.write(
            f"constexpr const {type.split('[')[0]} {name}[{len(values)}] = {{")
        for value in values:
            output.write(f"{value},")
        output.write("};\n")
    else:
        output.write(f"constexpr const {type} {name} = {values[0]};\n")


def parse_ap_params() -> tuple[int, int]:
    """Reads the AP parameters from the ectf_params.h file

    Raises:
        ValueError: If an AP parameter is missing

    Returns:
        tuple[int, int]: The attestation pin and replacement token
    """
    lines: list[str] = input_ap.readlines()
    attest_pin: int = 0x0
    replacement_token: int = 0x0
    for line in lines:
        if "AP_PIN" in line:
            attest_pin = int(line.split(" ")[2].strip(' \n"'))
        elif "AP_TOKEN" in line:
            replacement_token = int(line.split(" ")[2].strip(' \n"'), 16)
    if not attest_pin or not replacement_token:
        raise ValueError("Missing AP parameters")
    return attest_pin, replacement_token


attest_pin, replacement_token = parse_ap_params()
attest_pin = hash_pin(attest_pin, 1000)
replacement_token = hash_replacement(replacement_token)

write("uint8_t[]", "ATTEST_HASH", [f"{b}" for b in attest_pin])
write("uint8_t[]", "REPLACEMENT_HASH", [f"{b}" for b in replacement_token])

attest_pin = attest_pin.hex()
replacement_token = replacement_token.hex()
print(f"AP Params:\n{attest_pin=}\n{replacement_token=}")

input_ap.close()
output.close()
