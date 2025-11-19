from scsu.codecs.decoder import SCSUIncrementalDecoder
from scsu.codecs.encoder import SCSUIncrementalEncoder

__all__ = ["scsu_decode", "scsu_encode"]


def scsu_encode(data: str) -> bytes:
    encoder = SCSUIncrementalEncoder(errors="strict")
    return encoder.encode(s=data, final=True)


def scsu_decode(data: bytes) -> str:
    decoder = SCSUIncrementalDecoder(errors="strict")
    return decoder.decode(s=data, final=True)
