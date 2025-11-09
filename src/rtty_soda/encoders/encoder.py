from typing import Protocol

__all__ = ["Encoder"]


class Encoder(Protocol):
    @staticmethod
    def encode(data: bytes) -> str: ...

    @staticmethod
    def decode(data: str) -> bytes: ...
