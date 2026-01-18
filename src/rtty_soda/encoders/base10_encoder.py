from .encoder import Encoder
from .functions import int_to_bytes

__all__ = ["Base10Encoder"]


class Base10Encoder(Encoder):
    @staticmethod
    def encode(data: bytes) -> str:
        return str(int.from_bytes(data, byteorder="big", signed=False))

    @staticmethod
    def decode(data: str) -> bytes:
        return int_to_bytes(int(data))
