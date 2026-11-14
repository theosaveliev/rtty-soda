"""Short-nonce routines.

The code reduces ciphertext length by truncating the nonce.
This is needed to meet teletype hardware constraints in the
Underground Moscow museum.

The nonce is generated randomly as 12 bytes and extended to 24 bytes
by padding zeroes to the right.

Consequently, the effective nonce space is 96 bits, rather than 192
bits. For q encryptions per key, the approximate probability
of at least one nonce collision follows the birthday bound:

p ~= q * (q - 1) / 2^(96 + 1)
p ~= q^2 / 2^97

We target a collision probability <= 2^-32
(the magic number was taken from https://doc.libsodium.org/key_derivation?utm_source=chatgpt.com#nonce-extension)

q^2 / 2^97 <= 2^-32
q <= 2^32

p ~= (2^32)^2 / 2^97 = 2^-33
"""

from nacl.encoding import RawEncoder
from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.utils import random

__all__ = [
    "FULL_NONCE_LEN",
    "decrypt_public",
    "decrypt_secret",
    "encrypt_public",
    "encrypt_secret",
]

FULL_NONCE_LEN = 24
SHORT_NONCE_LEN = 12
PADDING = b"\x00"


def encrypt(box: Box | SecretBox, data: bytes) -> bytes:
    nonce_short = random(SHORT_NONCE_LEN)
    nonce_full = nonce_short.ljust(FULL_NONCE_LEN, PADDING)
    message = box.encrypt(plaintext=data, nonce=nonce_full, encoder=RawEncoder)
    return nonce_short + message.ciphertext


def decrypt(box: Box | SecretBox, data: bytes) -> bytes:
    nonce_short, ciphertext = data[:SHORT_NONCE_LEN], data[SHORT_NONCE_LEN:]
    nonce_full = nonce_short.ljust(FULL_NONCE_LEN, PADDING)
    return box.decrypt(ciphertext=ciphertext, nonce=nonce_full, encoder=RawEncoder)


def encrypt_public(private: PrivateKey, public: PublicKey, data: bytes) -> bytes:
    box = Box(private_key=private, public_key=public)
    return encrypt(box, data)


def decrypt_public(private: PrivateKey, public: PublicKey, data: bytes) -> bytes:
    box = Box(private_key=private, public_key=public)
    return decrypt(box, data)


def encrypt_secret(key: bytes, data: bytes) -> bytes:
    box = SecretBox(key=key, encoder=RawEncoder)
    return encrypt(box, data)


def decrypt_secret(key: bytes, data: bytes) -> bytes:
    box = SecretBox(key=key, encoder=RawEncoder)
    return decrypt(box, data)
