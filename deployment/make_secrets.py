from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

output = open("global_secrets_secure.h", "wt", encoding="utf-8")
output.write("""
#include <stdint.h>
#pragma once
""")


def gen_boot_keypair_A() -> tuple[bytes, bytes]:
    """Generate the Application Processor keypair

    Returns:
        tuple[bytes, bytes]: The private and public key
    """
    key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
        ec.SECP256K1(), default_backend()
    )
    return key.private_numbers().private_value.to_bytes(
        32, "big"
    ), key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def gen_boot_keypair_C() -> tuple[bytes, bytes]:
    """Generate the Component keypair

    Returns:
        tuple[bytes, bytes]: The private and public key
    """
    key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
        ec.SECP256K1(), default_backend()
    )
    return key.private_numbers().private_value.to_bytes(
        32, "big"
    ), key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def gen_replacement_keypair() -> tuple[bytes, bytes]:
    """Generate the replacement keypair

    Returns:
        tuple[bytes, bytes]: The private and public key
    """
    key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
        ec.SECP256K1(), default_backend()
    )
    return key.private_numbers().private_value.to_bytes(
        32, "big"
    ), key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def write(type: str, name: str, values: list[str]) -> None:
    """Write a constant to the global_secrets.h file

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


replacement_pub, replacement_priv = gen_replacement_keypair()
replacement_pub = replacement_pub.hex()
replacement_priv = replacement_priv.hex()
print(f"Replacement Params:\n{replacement_pub=}\n{replacement_priv=}\n")

keypair_A_priv, keypair_A_pub = gen_boot_keypair_A()
keypair_C_priv, keypair_C_pub = gen_boot_keypair_C()

write("uint8_t[]", "KEYPAIR_A_PUB", [f"{b}" for b in keypair_A_pub])
write("uint8_t[]", "KEYPAIR_A_PRIV", [f"{b}" for b in keypair_A_priv])
write("uint8_t[]", "KEYPAIR_C_PUB", [f"{b}" for b in keypair_C_pub])
write("uint8_t[]", "KEYPAIR_C_PRIV", [f"{b}" for b in keypair_C_priv])


keypair_A_priv = keypair_A_priv.hex()
keypair_A_pub = keypair_A_pub.hex()
print(f"Keypair A:\n{keypair_A_priv=}\n{keypair_A_pub=}\n")


keypair_C_priv = keypair_C_priv.hex()
keypair_C_pub = keypair_C_pub.hex()
print(f"Keypair C:\n{keypair_C_priv=}\n{keypair_C_pub=}\n")


# write("uint8_t[]", "REPLACEMENT_PUB", [f"{b}" for b in attest_key])


output.close()
