from .encoder import Encoder

__all__ = ["RawEncoder"]


class RawEncoder(Encoder):
    @staticmethod
    def encode(data: bytes) -> bytes:
        return data

    @staticmethod
    def decode(data: bytes) -> bytes:
        return data
