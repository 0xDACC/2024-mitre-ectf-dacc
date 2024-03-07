import secrets

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

output = open("global_secrets_secure.h", "wt", encoding="utf-8")
output.write(
    """
#include <stdint.h>
#pragma once
"""
)


def gen_keypair() -> tuple[bytes, bytes]:
    """Generate the Application Processor keypair

    Returns:
        tuple[bytes, bytes]: The private and public key
    """
    key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
        ec.SECP256K1(), default_backend()
    )
    return (
        key.private_numbers().private_value.to_bytes(32, "big"),
        key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[
            1:
        ],
    )


def write(type: str, name: str, values: list[str], ap: bool, comp: bool) -> None:
    """Write a constant to the global_secrets.h file

    Args:
        type (str): Type of the constant
        name (str): Variable name
        values (list[str]): Value of the constant
        ap (bool): If the constant is for the Application Processor
        comp (bool): If the constant is for the Component
    """
    if not ap and not comp:
        raise ValueError(
            "Must specify at least one of ap or comp as True")
    if ap:
        output.write("#if AP\n")
        if "[" in type and "]" in type:
            output.write(
                f"constexpr const {type.split('[')[0]} {name}[{len(values)}] = {{")
            for value in values:
                output.write(f"{value},")
            output.write("};\n")
        else:
            output.write(f"constexpr const {type} {name} = {values[0]};\n")
        output.write("#endif\n")
    if comp:
        output.write("#if COMP\n")
        if "[" in type and "]" in type:
            output.write(
                f"constexpr const {type.split('[')[0]} {name}[{len(values)}] = {{")
            for value in values:
                output.write(f"{value},")
            output.write("};\n")
        else:
            output.write(f"constexpr const {type} {name} = {values[0]};\n")
        output.write("#endif\n")


keypair_A_priv, keypair_A_pub = gen_keypair()
keypair_C_priv, keypair_C_pub = gen_keypair()
replacement_priv, replacement_pub = gen_keypair()
attest_A_priv, attest_A_pub = gen_keypair()
attest_C_priv, attest_C_pub = gen_keypair()

hmac_key = secrets.token_bytes(32)
attest_key_unwrapped = secrets.token_bytes(16)
attest_nonce = secrets.token_bytes(16)

write("uint8_t[]", "BOOT_A_PUB", [f"{b}" for b in keypair_A_pub], False, True)
write("uint8_t[]", "BOOT_A_PRIV", [
      f"{b}" for b in keypair_A_priv], True, False)
write("uint8_t[]", "BOOT_C_PUB", [f"{b}" for b in keypair_C_pub], True, False)
write("uint8_t[]", "BOOT_C_PRIV", [
      f"{b}" for b in keypair_C_priv], False, True)
write("uint8_t[]", "REPLACEMENT_PUB", [
      f"{b}" for b in replacement_pub], True, False)
write("uint8_t[]", "REPLACEMENT_PRIV", [
      f"{b}" for b in replacement_priv], False, True)
write("uint8_t[]", "ATTEST_A_PUB", [f"{b}" for b in attest_A_pub], False, True)
write("uint8_t[]", "ATTEST_A_PRIV", [
      f"{b}" for b in attest_A_priv], True, False)
write("uint8_t[]", "ATTEST_C_PUB", [f"{b}" for b in attest_C_pub], True, False)
write("uint8_t[]", "ATTEST_C_PRIV", [
      f"{b}" for b in attest_C_priv], False, True)

write("uint8_t[]", "HMAC_KEY", [f"{b}" for b in hmac_key], True, True)
write("uint8_t[]", "ATTEST_UNWRAPPED_NONCE", [
      f"{b}" for b in attest_nonce], True, False)

output.write(f"//#define ATTEST_KEY_UNWRAPPED {attest_key_unwrapped.hex()}\n")
output.write(f"//#define ATTEST_NONCE {attest_nonce.hex()}\n")

keypair_A_priv = keypair_A_priv.hex()
keypair_A_pub = keypair_A_pub.hex()

keypair_C_priv = keypair_C_priv.hex()
keypair_C_pub = keypair_C_pub.hex()

# write("uint8_t[]", "REPLACEMENT_PUB", [f"{b}" for b in attest_key])

output.close()
