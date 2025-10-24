import base64
from typing import ClassVar

__all__ = ["Base64Encoder"]


class Base64Encoder:
    is_binary: ClassVar = False

    @staticmethod
    def encode(data: bytes) -> bytes:
        return base64.b64encode(data)

    @staticmethod
    def decode(data: bytes) -> bytes:
        return base64.b64decode(data)
