from .base26_encoder import Base26Encoder
from .base31_encoder import Base31Encoder
from .base36_encoder import Base36Encoder
from .base64_encoder import Base64Encoder
from .base94_encoder import Base94Encoder
from .encoder import Encoder
from .functions import decode_bytes, encode_str
from .raw_encoder import RawEncoder

__all__ = [
    "ENCODERS",
    "Base26Encoder",
    "Base31Encoder",
    "Base36Encoder",
    "Base64Encoder",
    "Base94Encoder",
    "Encoder",
    "RawEncoder",
    "decode_bytes",
    "encode_str",
]

ENCODERS: dict[str, Encoder] = {
    "base26": Base26Encoder,
    "base31": Base31Encoder,
    "base36": Base36Encoder,
    "base64": Base64Encoder,
    "base94": Base94Encoder,
    "binary": RawEncoder,
}
