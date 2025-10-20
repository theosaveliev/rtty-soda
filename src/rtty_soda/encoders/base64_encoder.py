import base64

from .encoder import Encoder

__all__ = ["Base64Encoder"]


class Base64Encoder(Encoder):
    @staticmethod
    def encode(data: bytes) -> bytes:
        return base64.b64encode(data)

    @staticmethod
    def decode(data: bytes) -> bytes:
        return base64.b64decode(data)
