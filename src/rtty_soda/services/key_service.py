from typing import TYPE_CHECKING

from nacl.public import PrivateKey

from rtty_soda.cryptography import kdf, secret
from rtty_soda.encoders import ENCODERS, encode_str

from .service import Service

if TYPE_CHECKING:
    from rtty_soda.cryptography.secret import SecretKeyOp
    from rtty_soda.formatters import Formatter
    from rtty_soda.interfaces import Reader, Writer

__all__ = ["KeyService"]


class KeyService(Service):
    def __init__(
        self, encoding: str, formatter: Formatter, writer: Writer, verbose: bool
    ) -> None:
        super().__init__(formatter, writer, verbose)
        self.encoder = ENCODERS.get(encoding)

    def genkey(self, passphrase: str | None) -> None:
        priv_bytes = bytes(PrivateKey.generate())
        protected = self.protect(private_key=priv_bytes, passphrase=passphrase)
        self.write_output(protected, self.encoder)

    def pubkey(self, private_key: Reader, passphrase: str | None) -> None:
        priv_bytes = self.read_input(private_key, self.encoder)
        unprotected = self.unprotect(private_key=priv_bytes, passphrase=passphrase)
        priv_key = PrivateKey(unprotected)
        public_key = bytes(priv_key.public_key)
        self.write_output(public_key, self.encoder)

    def kdf(self, password: Reader, kdf_profile: str, passphrase: str | None) -> None:
        key_bytes = self.derive_key(password, kdf_profile)
        protected = self.protect(private_key=key_bytes, passphrase=passphrase)
        self.write_output(protected, self.encoder)

    @staticmethod
    def derive_key(password: str | Reader, kdf_profile: str) -> bytes:
        prof = kdf.KDF_PROFILES[kdf_profile]
        pw_str = password if isinstance(password, str) else password.read_str()
        pw_bytes = encode_str(pw_str.strip())
        return kdf.kdf(password=pw_bytes, profile=prof)

    @staticmethod
    def passphrase_flow(
        private_key: bytes, passphrase: str | None, operation: SecretKeyOp
    ) -> bytes:
        if passphrase is None:
            return private_key

        skey = KeyService.derive_key(passphrase, "sensitive")
        return operation(key=skey, data=private_key)

    @staticmethod
    def protect(private_key: bytes, passphrase: str | None) -> bytes:
        return KeyService.passphrase_flow(
            private_key=private_key, passphrase=passphrase, operation=secret.encrypt
        )

    @staticmethod
    def unprotect(private_key: bytes, passphrase: str | None) -> bytes:
        return KeyService.passphrase_flow(
            private_key=private_key, passphrase=passphrase, operation=secret.decrypt
        )
