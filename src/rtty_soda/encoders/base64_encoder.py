import base64

from .encoder import Encoder
from .functions import decode_bytes, encode_str

__all__ = ["Base64Encoder"]


class Base64Encoder(Encoder):
    @staticmethod
    def encode(data: bytes) -> str:
        return decode_bytes(base64.b64encode(data))

    @staticmethod
    def decode(data: str) -> bytes:
        return base64.b64decode(encode_str(data))
