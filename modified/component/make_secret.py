import secrets

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

input_component = open("inc/ectf_params.h", "rt", encoding="utf-8")
output = open("inc/global_secrets_secure.h", "wt", encoding="utf-8")


def wrap_key(key: bytes, nonce: bytes, wrapper: bytes) -> bytes:
    cipher = Cipher(AES(key), mode=CTR(nonce), backend=default_backend()).encryptor()
    return cipher.update(wrapper) + cipher.finalize()


def encrypt_attestation(
    loc: str, date: str, cust: str, nonce: bytes, key: bytes
) -> tuple[bytes, bytes, bytes]:
    cipher = Cipher(AES(key), mode=CTR(nonce), backend=default_backend()).encryptor()
    return (
        cipher.update(loc.encode()),
        cipher.update(date.encode()),
        cipher.update(cust.encode()) + cipher.finalize(),
    )


def write(type: str, name: str, values: list[str]) -> None:
    if "[" in type and "]" in type:
        output.write(f"constexpr const {type.split('[')[0]} {name}[{len(values)}] = {{")
        for value in values:
            output.write(f"{value},")
        output.write("};\n")
    else:
        output.write(f"constexpr const {type} {name} = {values[0]};\n")


def parse_component_attestation() -> tuple[str, str, str]:
    lines = input_component.readlines()
    attest_loc = ""
    attest_date = ""
    attest_cust = ""
    for line in lines:
        if "ATTESTATION_LOC" in line:
            attest_loc = line.split(" ")[2].strip(' \n"')
        elif "ATTESTATION_DATE" in line:
            attest_date = line.split(" ")[2].strip(' \n"')
        elif "ATTESTATION_CUSTOMER" in line:
            attest_cust = line.split(" ")[2].strip(' \n"')
    if not attest_loc or not attest_date or not attest_cust:
        raise ValueError("Missing attestation parameters")
    for _ in range(64 - len(attest_loc)):
        attest_loc += "\x00"
    for _ in range(64 - len(attest_date)):
        attest_date += "\x00"
    for _ in range(64 - len(attest_cust)):
        attest_cust += "\x00"
    return attest_loc, attest_date, attest_cust


attest_loc, attest_date, attest_cust = parse_component_attestation()
attest_key = secrets.token_bytes(16)
attest_nonce = secrets.token_bytes(16)
attest_loc, attest_date, attest_cust = encrypt_attestation(
    attest_loc,
    attest_date,
    attest_cust,
    attest_nonce,
    attest_key,
)
attest_loc = attest_loc.hex()
attest_date = attest_date.hex()
attest_cust = attest_cust.hex()
attest_key = attest_key.hex()
attest_nonce = attest_nonce.hex()
print(
    f"Attestation Params:\n{attest_key=}\n{attest_nonce=}\n{attest_loc=}\n{attest_date=}\n{attest_cust=}\n"
)

# write("int", "pin", [str(random.randint(1000, 9999))])
# write("int[]", "attest_keypair", [str(random.randint(1000, 9999)), str(random.randint(1000, 9999))])
