from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

output = open("global_secrets.h", "wt", encoding="utf-8")


def gen_boot_keypair_A() -> tuple[bytes, bytes]:
    key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
        ec.SECP256K1(), default_backend()
    )
    return key.private_numbers().private_value.to_bytes(
        32, "big"
    ), key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def gen_boot_keypair_B() -> tuple[bytes, bytes]:
    key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
        ec.SECP256K1(), default_backend()
    )
    return key.private_numbers().private_value.to_bytes(
        32, "big"
    ), key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def gen_boot_keypair_C() -> tuple[bytes, bytes]:
    key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
        ec.SECP256K1(), default_backend()
    )
    return key.private_numbers().private_value.to_bytes(
        32, "big"
    ), key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def gen_boot_keypair_D() -> tuple[bytes, bytes]:
    key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
        ec.SECP256K1(), default_backend()
    )
    return key.private_numbers().private_value.to_bytes(
        32, "big"
    ), key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def write(type: str, name: str, values: list[str]) -> None:
    if "[" in type and "]" in type:
        output.write(f"constexpr const {type.split('[')[0]} {name}[{len(values)}] = {{")
        for value in values:
            output.write(f"{value},")
        output.write("};\n")
    else:
        output.write(f"constexpr const {type} {name} = {values[0]};\n")


def generate_replacement_keypair() -> tuple[bytes, bytes]:
    key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
        ec.SECP256K1(), default_backend()
    )
    return key.private_numbers().private_value.to_bytes(
        32, "big"
    ), key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


replacement_pub, replacement_priv = generate_replacement_keypair()
replacement_pub = replacement_pub.hex()
replacement_priv = replacement_priv.hex()
print(f"Replacement Params:\n{replacement_pub=}\n{replacement_priv=}\n")

keypair_A_priv, keypair_A_pub = gen_boot_keypair_A()
keypair_B_priv, keypair_B_pub = gen_boot_keypair_B()
keypair_C_priv, keypair_C_pub = gen_boot_keypair_C()
keypair_D_priv, keypair_D_pub = gen_boot_keypair_D()

keypair_A_priv = keypair_A_priv.hex()
keypair_A_pub = keypair_A_pub.hex()
print(f"Keypair A:\n{keypair_A_priv=}\n{keypair_A_pub=}\n")

keypair_B_priv = keypair_B_priv.hex()
keypair_B_pub = keypair_B_pub.hex()
print(f"Keypair B:\n{keypair_B_priv=}\n{keypair_B_pub=}\n")

keypair_C_priv = keypair_C_priv.hex()
keypair_C_pub = keypair_C_pub.hex()
print(f"Keypair C:\n{keypair_C_priv=}\n{keypair_C_pub=}\n")

keypair_D_priv = keypair_D_priv.hex()
keypair_D_pub = keypair_D_pub.hex()
print(f"Keypair D:\n{keypair_D_priv=}\n{keypair_D_pub=}")

# write("int", "pin", [str(random.randint(1000, 9999))])
# write("int[]", "attest_keypair", [str(random.randint(1000, 9999)), str(random.randint(1000, 9999))])
