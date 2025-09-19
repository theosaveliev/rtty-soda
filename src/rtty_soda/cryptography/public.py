from nacl.public import Box, PrivateKey, PublicKey
from nacl.utils import EncryptedMessage

from rtty_soda.encoders import Encoder

__all__ = ["decrypt", "encrypt"]


def encrypt(
    private: PrivateKey, public: PublicKey, data: bytes, out_enc: Encoder
) -> EncryptedMessage:
    box = Box(private, public)
    return box.encrypt(data, encoder=out_enc)


def decrypt(
    private: PrivateKey, public: PublicKey, data: bytes, in_enc: Encoder
) -> bytes:
    box = Box(private, public)
    return box.decrypt(data, encoder=in_enc)
