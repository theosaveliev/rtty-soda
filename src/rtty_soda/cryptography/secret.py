from nacl.encoding import Encoder
from nacl.secret import SecretBox
from nacl.utils import EncryptedMessage

__all__ = ["decrypt", "encrypt"]


def encrypt(
    key: bytes, data: bytes, key_enc: Encoder, out_enc: Encoder
) -> EncryptedMessage:
    box = SecretBox(key, key_enc)
    return box.encrypt(data, encoder=out_enc)


def decrypt(key: bytes, data: bytes, key_enc: Encoder, in_enc: Encoder) -> bytes:
    box = SecretBox(key, key_enc)
    return box.decrypt(data, encoder=in_enc)
