from typing import TYPE_CHECKING

from nacl.encoding import RawEncoder
from nacl.secret import SecretBox

if TYPE_CHECKING:
    from nacl.utils import EncryptedMessage


__all__ = ["decrypt", "encrypt"]


def encrypt(key: bytes, data: bytes) -> EncryptedMessage:
    box = SecretBox(key=key, encoder=RawEncoder)
    return box.encrypt(plaintext=data, encoder=RawEncoder)


def decrypt(key: bytes, data: bytes) -> bytes:
    box = SecretBox(key=key, encoder=RawEncoder)
    return box.decrypt(ciphertext=data, encoder=RawEncoder)
