from typing import TYPE_CHECKING

from nacl.public import PrivateKey

from rtty_soda.cryptography import kdf
from rtty_soda.encoders import ENCODERS, encode_str

from .service import Service

if TYPE_CHECKING:
    from rtty_soda.formatters import Formatter
    from rtty_soda.interfaces import Reader, Writer

__all__ = ["KeyService"]


class KeyService(Service):
    def __init__(
        self, encoding: str, formatter: Formatter, writer: Writer, verbose: bool
    ) -> None:
        super().__init__(formatter, writer, verbose)
        self.encoder = ENCODERS.get(encoding)

    def genkey(self) -> None:
        key = bytes(PrivateKey.generate())
        self.write_output(key, self.encoder)

    def pubkey(self, priv_key: Reader) -> None:
        priv_bytes = self.read_input(priv_key, self.encoder)
        priv = PrivateKey(priv_bytes)
        pub = bytes(priv.public_key)
        self.write_output(pub, self.encoder)

    @staticmethod
    def derive_key(password: Reader, kdf_profile: str) -> bytes:
        prof = kdf.KDF_PROFILES[kdf_profile]
        pw_str = password.read_str().strip()
        pw_bytes = encode_str(pw_str)
        return kdf.kdf(password=pw_bytes, profile=prof)

    def kdf(self, password: Reader, kdf_profile: str) -> None:
        key = self.derive_key(password, kdf_profile)
        self.write_output(key, self.encoder)
