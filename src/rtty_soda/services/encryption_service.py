from typing import TYPE_CHECKING

from nacl.public import PrivateKey, PublicKey

from rtty_soda.archivers import ARCHIVERS, UNARCHIVERS
from rtty_soda.cryptography import public, secret
from rtty_soda.encoders import ENCODERS, encode_str, scsu_decode, scsu_encode

from .key_service import KeyService
from .service import Service

if TYPE_CHECKING:
    from collections.abc import Callable

    from rtty_soda.formatters import Formatter
    from rtty_soda.interfaces import Reader, Writer

__all__ = ["EncryptionService", "Pipe"]

type Pipe = Callable[[bytes], bytes]


class EncryptionService(Service):
    def __init__(
        self,
        text_mode: bool,
        key_encoding: str,
        data_encoding: str,
        compression: str,
        formatter: Formatter | None,
        writer: Writer,
        verbose: bool,
    ) -> None:
        super().__init__(formatter, writer, verbose)
        self.text_mode = text_mode
        self.key_encoder = ENCODERS.get(key_encoding)
        self.data_encoder = ENCODERS.get(data_encoding)
        self.archiver = ARCHIVERS.get(compression)
        self.unarchiver = UNARCHIVERS.get(compression)

    def encryption_flow(self, message: Reader, encrypt: Pipe) -> None:
        if self.text_mode:
            text = message.read_str().strip()
            plaintext_len = len(text)
            data = scsu_encode(text)
        else:
            data = message.read_bytes()
            plaintext_len = len(data)

        if self.archiver is not None:
            data = self.archiver(data)

        data = encrypt(data)
        buff = self.format_data(data, self.data_encoder)
        writer = self.writer
        writer.write_bytes(buff.data)
        if self.verbose:
            overhead = buff.length / plaintext_len
            writer.write_diag(f"Plaintext: {plaintext_len}")
            writer.write_diag(f"Ciphertext: {buff.length}")
            writer.write_diag(f"Overhead: {overhead:.3f}")
            writer.write_diag(f"Groups: {buff.groups}")

    def read_private_key(self, key: Reader, passphrase: str | None) -> bytes:
        key_bytes = self.read_input(key, self.key_encoder)
        return KeyService.unprotect(private_key=key_bytes, passphrase=passphrase)

    def encrypt_public(
        self,
        private_key: Reader,
        passphrase: str | None,
        public_key: Reader,
        message: Reader,
    ) -> None:
        priv_bytes = self.read_private_key(key=private_key, passphrase=passphrase)
        priv_key = PrivateKey(priv_bytes)
        pub_bytes = self.read_input(public_key, self.key_encoder)
        pub_key = PublicKey(pub_bytes)

        def encrypt(data: bytes) -> bytes:
            return public.encrypt(private=priv_key, public=pub_key, data=data)

        self.encryption_flow(message, encrypt)

    def encrypt_secret(
        self, key: Reader, passphrase: str | None, message: Reader
    ) -> None:
        key_bytes = self.read_private_key(key=key, passphrase=passphrase)

        def encrypt(data: bytes) -> bytes:
            return secret.encrypt(key=key_bytes, data=data)

        self.encryption_flow(message, encrypt)

    def encrypt_password(
        self, password: Reader, message: Reader, kdf_profile: str
    ) -> None:
        key_bytes = KeyService.derive_key(password, kdf_profile)

        def encrypt(data: bytes) -> bytes:
            return secret.encrypt(key_bytes, data)

        self.encryption_flow(message, encrypt)

    def decryption_flow(self, message: Reader, decrypt: Pipe) -> None:
        data = self.read_input(message, self.data_encoder)
        data = decrypt(data)
        if self.unarchiver is not None:
            data = self.unarchiver(data)

        if self.text_mode:
            data = encode_str(scsu_decode(data))

        self.writer.write_bytes(data)

    def decrypt_public(
        self,
        private_key: Reader,
        passphrase: str | None,
        public_key: Reader,
        message: Reader,
    ) -> None:
        priv_bytes = self.read_private_key(key=private_key, passphrase=passphrase)
        priv_key = PrivateKey(priv_bytes)
        pub_bytes = self.read_input(public_key, self.key_encoder)
        pub_key = PublicKey(pub_bytes)

        def decrypt(data: bytes) -> bytes:
            return public.decrypt(private=priv_key, public=pub_key, data=data)

        self.decryption_flow(message, decrypt)

    def decrypt_secret(
        self, key: Reader, passphrase: str | None, message: Reader
    ) -> None:
        key_bytes = self.read_private_key(key=key, passphrase=passphrase)

        def decrypt(data: bytes) -> bytes:
            return secret.decrypt(key=key_bytes, data=data)

        self.decryption_flow(message, decrypt)

    def decrypt_password(
        self, password: Reader, message: Reader, kdf_profile: str
    ) -> None:
        key_bytes = KeyService.derive_key(password, kdf_profile)

        def decrypt(data: bytes) -> bytes:
            return secret.decrypt(key_bytes, data)

        self.decryption_flow(message, decrypt)
