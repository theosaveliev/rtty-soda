from typing import ClassVar

__all__ = ["RawEncoder"]


class RawEncoder:
    is_binary: ClassVar = True

    @staticmethod
    def encode(data: bytes) -> bytes:
        return data

    @staticmethod
    def decode(data: bytes) -> bytes:
        return data
