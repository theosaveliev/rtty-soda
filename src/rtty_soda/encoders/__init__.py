from .concrete import (
    Base10Encoder,
    Base26Encoder,
    Base31Encoder,
    Base32Encoder,
    Base36Encoder,
    Base64Encoder,
    Base94Encoder,
    decode_bytes,
    encode_str,
)
from .encoder import Encoder
from .encoder_base import EncoderBase
from .scsu import scsu_decode, scsu_encode

__all__ = [
    "ENCODERS",
    "Base10Encoder",
    "Base26Encoder",
    "Base31Encoder",
    "Base32Encoder",
    "Base36Encoder",
    "Base64Encoder",
    "Base94Encoder",
    "Encoder",
    "EncoderBase",
    "decode_bytes",
    "encode_str",
    "scsu_decode",
    "scsu_encode",
]

ENCODERS: dict[str, Encoder | None] = {
    "base10": Base10Encoder(),
    "base26": Base26Encoder(),
    "base31": Base31Encoder(),
    "base32": Base32Encoder(),
    "base36": Base36Encoder(),
    "base64": Base64Encoder(),
    "base94": Base94Encoder(),
    "binary": None,
}
