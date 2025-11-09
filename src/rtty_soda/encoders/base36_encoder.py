import string

from .encoder import Encoder
from .functions import base_to_bytes, bytes_to_base

__all__ = ["ALPHABET", "Base36Encoder"]

ALPHABET = string.digits + string.ascii_uppercase


class Base36Encoder(Encoder):
    @staticmethod
    def encode(data: bytes) -> str:
        return bytes_to_base(data, ALPHABET)

    @staticmethod
    def decode(data: str) -> bytes:
        return base_to_bytes(data, ALPHABET)
