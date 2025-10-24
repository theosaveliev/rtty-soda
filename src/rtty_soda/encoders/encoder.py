from typing import Protocol

__all__ = ["Encoder"]


class Encoder(Protocol):
    is_binary: bool

    @staticmethod
    def encode(data: bytes) -> bytes: ...

    @staticmethod
    def decode(data: bytes) -> bytes: ...
