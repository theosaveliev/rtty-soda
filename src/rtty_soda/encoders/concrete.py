import base64
import string
from typing import ClassVar

from .encoder import Encoder
from .encoder_base import EncoderBase

__all__ = [
    "Base10Encoder",
    "Base26Encoder",
    "Base31Encoder",
    "Base32Encoder",
    "Base36Encoder",
    "Base64Encoder",
    "Base94Encoder",
    "decode_bytes",
    "encode_str",
]


def encode_str(data: str) -> bytes:
    return data.encode(encoding="utf-8", errors="strict")


def decode_bytes(data: bytes) -> str:
    return data.decode(encoding="utf-8", errors="strict")


class Base10Encoder(EncoderBase, Encoder):
    alphabet: ClassVar[str] = string.digits


class Base26Encoder(EncoderBase, Encoder):
    alphabet: ClassVar[str] = string.ascii_uppercase


class Base31Encoder(EncoderBase, Encoder):
    alphabet: ClassVar[str] = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЬЫЭЮЯ"


class Base32Encoder(Encoder):
    @classmethod
    def encode(cls, data: bytes) -> str:
        return decode_bytes(base64.b32encode(data))

    @classmethod
    def decode(cls, data: str) -> bytes:
        return base64.b32decode(data)


class Base36Encoder(EncoderBase, Encoder):
    alphabet: ClassVar[str] = string.digits + string.ascii_uppercase


class Base64Encoder(Encoder):
    @classmethod
    def encode(cls, data: bytes) -> str:
        return decode_bytes(base64.b64encode(data))

    @classmethod
    def decode(cls, data: str) -> bytes:
        return base64.b64decode(data)


class Base94Encoder(EncoderBase, Encoder):
    alphabet: ClassVar[str] = "".join([chr(i) for i in range(33, 127)])
