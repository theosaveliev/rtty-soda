from typing import TYPE_CHECKING

from nacl.encoding import RawEncoder
from nacl.public import Box, PrivateKey, PublicKey

if TYPE_CHECKING:
    from nacl.utils import EncryptedMessage


__all__ = ["decrypt", "encrypt"]


def encrypt(private: PrivateKey, public: PublicKey, data: bytes) -> EncryptedMessage:
    box = Box(private_key=private, public_key=public)
    return box.encrypt(plaintext=data, encoder=RawEncoder)


def decrypt(private: PrivateKey, public: PublicKey, data: bytes) -> bytes:
    box = Box(private_key=private, public_key=public)
    return box.decrypt(ciphertext=data, encoder=RawEncoder)
