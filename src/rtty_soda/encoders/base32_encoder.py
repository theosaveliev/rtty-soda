import base64

from .encoder import Encoder
from .functions import decode_bytes

__all__ = ["Base32Encoder"]


class Base32Encoder(Encoder):
    @staticmethod
    def encode(data: bytes) -> str:
        return decode_bytes(base64.b32encode(data))

    @staticmethod
    def decode(data: str) -> bytes:
        return base64.b32decode(data)
