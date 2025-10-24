from typing import ClassVar

from .functions import base_to_bytes, bytes_to_base, decode_bytes, encode_str

__all__ = ["ALPHABET", "Base31Encoder"]

ALPHABET = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЬЫЭЮЯ"


class Base31Encoder:
    is_binary: ClassVar = False

    @staticmethod
    def encode(data: bytes) -> bytes:
        return encode_str(bytes_to_base(data, ALPHABET))

    @staticmethod
    def decode(data: bytes) -> bytes:
        return base_to_bytes(decode_bytes(data), ALPHABET)
