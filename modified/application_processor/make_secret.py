from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.hashes import Hash, SHA256

input_ap = open("inc/ectf_params.h", "rt", encoding="utf-8")
output = open("inc/global_secrets_secure.h", "wt", encoding="utf-8")


def wrap_key(key: bytes, nonce: bytes, wrapper: bytes) -> bytes:
    cipher = Cipher(AES(key), mode=CTR(nonce), backend=default_backend()).encryptor()
    return cipher.update(wrapper) + cipher.finalize()


def hash_pin(pin: int, iterations: int) -> bytes:
    hasher = Hash(SHA256(), backend=default_backend())
    for _ in range(iterations):
        hasher.update(pin.to_bytes(6, "big"))
    return hasher.finalize()


def hash_replacement(token: int, iterations: int) -> bytes:
    hasher = Hash(SHA256(), backend=default_backend())
    for _ in range(iterations):
        hasher.update(token.to_bytes(16, "big"))
    return hasher.finalize()


def write(type: str, name: str, values: list[str]) -> None:
    if "[" in type and "]" in type:
        output.write(f"constexpr const {type.split('[')[0]} {name}[{len(values)}] = {{")
        for value in values:
            output.write(f"{value},")
        output.write("};\n")
    else:
        output.write(f"constexpr const {type} {name} = {values[0]};\n")


def parse_ap_params() -> tuple[int, int]:
    lines = input_ap.readlines()
    attest_pin = 0x0
    replacement_token = 0x0
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
replacement_token = hash_replacement(replacement_token, 1000)

attest_pin = attest_pin.hex()
replacement_token = replacement_token.hex()
print(f"AP Params:\n{attest_pin=}\n{replacement_token=}")

# write("int", "pin", [str(random.randint(1000, 9999))])
# write("int[]", "attest_keypair", [str(random.randint(1000, 9999)), str(random.randint(1000, 9999))])
