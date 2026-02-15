from typing import Protocol

__all__ = ["Encoder"]


class Encoder(Protocol):
    @classmethod
    def encode(cls, data: bytes) -> str: ...

    @classmethod
    def decode(cls, data: str) -> bytes: ...
