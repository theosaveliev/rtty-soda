from typing import TYPE_CHECKING

import click
from click_aliases import ClickAliasedGroup

from rtty_soda.cli import CliOptions, CliReader, CliTypes, CliWriter
from rtty_soda.formatters import FixedFormatter
from rtty_soda.services import EncodingService, EncryptionService, KeyService
from rtty_soda.totp import GoogleAuthenticator

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["cli"]


CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


@click.group(cls=ClickAliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.version_option(package_name="rtty-soda")
def cli() -> None:
    pass


@cli.command()  # pyright: ignore[reportAny]
@CliOptions.key_passphrase
@CliOptions.short_key_encoding
@CliOptions.output_file
@CliOptions.group_len
@CliOptions.line_len
@CliOptions.padding
@CliOptions.verbose
def genkey_cmd(
    key_passphrase: str | None,
    encoding: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None:
    """Generate private/secret key."""
    formatter = FixedFormatter(group_len, line_len, padding)
    writer = CliWriter(output_file)
    service = KeyService(encoding, formatter, writer, verbose)
    service.genkey(passphrase=key_passphrase)


@cli.command()  # pyright: ignore[reportAny]
@click.argument("private_key_file", type=CliTypes.IN_PATH)
@CliOptions.key_passphrase
@CliOptions.short_key_encoding
@CliOptions.output_file
@CliOptions.group_len
@CliOptions.line_len
@CliOptions.padding
@CliOptions.verbose
def pubkey_cmd(
    private_key_file: Path,
    key_passphrase: str | None,
    encoding: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None:
    """Get public key."""
    formatter = FixedFormatter(group_len, line_len, padding)
    writer = CliWriter(output_file)
    service = KeyService(encoding, formatter, writer, verbose)
    private_key = CliReader(private_key_file)
    service.pubkey(private_key=private_key, passphrase=key_passphrase)


@cli.command()  # pyright: ignore[reportAny]
@click.argument("password_file", type=CliTypes.IN_PATH)
@CliOptions.key_passphrase
@CliOptions.short_key_encoding
@CliOptions.short_kdf_profile
@CliOptions.output_file
@CliOptions.group_len
@CliOptions.line_len
@CliOptions.padding
@CliOptions.verbose
def kdf_cmd(
    password_file: Path,
    key_passphrase: str | None,
    encoding: str,
    profile: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None:
    """Key derivation function."""
    formatter = FixedFormatter(group_len, line_len, padding)
    writer = CliWriter(output_file)
    service = KeyService(encoding, formatter, writer, verbose)
    password = CliReader(password_file)
    service.kdf(password=password, kdf_profile=profile, passphrase=key_passphrase)


@cli.command(aliases=["e"])  # pyright: ignore[reportAny]
@click.argument("private_key_file", type=CliTypes.IN_PATH)
@click.argument("public_key_file", type=CliTypes.IN_PATH)
@click.argument("message_file", type=CliTypes.IN_PATH)
@CliOptions.text
@CliOptions.key_passphrase
@CliOptions.key_encoding
@CliOptions.data_encoding
@CliOptions.compression
@CliOptions.output_file
@CliOptions.group_len
@CliOptions.line_len
@CliOptions.padding
@CliOptions.verbose
def encrypt_public_cmd(
    private_key_file: Path,
    public_key_file: Path,
    message_file: Path,
    text: bool,
    key_passphrase: str | None,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None:
    """Encrypt message (public)."""
    formatter = FixedFormatter(group_len, line_len, padding)
    writer = CliWriter(output_file)
    service = EncryptionService(
        text_mode=text,
        key_encoding=key_encoding,
        data_encoding=data_encoding,
        compression=compression,
        formatter=formatter,
        writer=writer,
        verbose=verbose,
    )
    private_key = CliReader(private_key_file)
    public_key = CliReader(public_key_file)
    message = CliReader(message_file)
    service.encrypt_public(
        private_key=private_key,
        passphrase=key_passphrase,
        public_key=public_key,
        message=message,
    )


@cli.command(aliases=["es"])  # pyright: ignore[reportAny]
@click.argument("key_file", type=CliTypes.IN_PATH)
@click.argument("message_file", type=CliTypes.IN_PATH)
@CliOptions.text
@CliOptions.key_passphrase
@CliOptions.key_encoding
@CliOptions.data_encoding
@CliOptions.compression
@CliOptions.output_file
@CliOptions.group_len
@CliOptions.line_len
@CliOptions.padding
@CliOptions.verbose
def encrypt_secret_cmd(
    key_file: Path,
    message_file: Path,
    text: bool,
    key_passphrase: str | None,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None:
    """Encrypt message (secret)."""
    formatter = FixedFormatter(group_len, line_len, padding)
    writer = CliWriter(output_file)
    service = EncryptionService(
        text_mode=text,
        key_encoding=key_encoding,
        data_encoding=data_encoding,
        compression=compression,
        formatter=formatter,
        writer=writer,
        verbose=verbose,
    )
    key = CliReader(key_file)
    message = CliReader(message_file)
    service.encrypt_secret(key=key, passphrase=key_passphrase, message=message)


@cli.command(aliases=["ep"])  # pyright: ignore[reportAny]
@click.argument("password_file", type=CliTypes.IN_PATH)
@click.argument("message_file", type=CliTypes.IN_PATH)
@CliOptions.text
@CliOptions.kdf_profile
@CliOptions.data_encoding
@CliOptions.compression
@CliOptions.output_file
@CliOptions.group_len
@CliOptions.line_len
@CliOptions.padding
@CliOptions.verbose
def encrypt_password_cmd(
    password_file: Path,
    message_file: Path,
    text: bool,
    kdf_profile: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None:
    """Encrypt message (password)."""
    formatter = FixedFormatter(group_len, line_len, padding)
    writer = CliWriter(output_file)
    service = EncryptionService(
        text_mode=text,
        key_encoding="binary",
        data_encoding=data_encoding,
        compression=compression,
        formatter=formatter,
        writer=writer,
        verbose=verbose,
    )
    pw = CliReader(password_file)
    message = CliReader(message_file)
    service.encrypt_password(password=pw, message=message, kdf_profile=kdf_profile)


@cli.command(aliases=["d"])  # pyright: ignore[reportAny]
@click.argument("private_key_file", type=CliTypes.IN_PATH)
@click.argument("public_key_file", type=CliTypes.IN_PATH)
@click.argument("message_file", type=CliTypes.IN_PATH)
@CliOptions.text
@CliOptions.key_passphrase
@CliOptions.key_encoding
@CliOptions.data_encoding
@CliOptions.compression
@CliOptions.output_file
def decrypt_public_cmd(
    private_key_file: Path,
    public_key_file: Path,
    message_file: Path,
    text: bool,
    key_passphrase: str | None,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None:
    """Decrypt message (public)."""
    writer = CliWriter(output_file)
    service = EncryptionService(
        text_mode=text,
        key_encoding=key_encoding,
        data_encoding=data_encoding,
        compression=compression,
        formatter=None,
        writer=writer,
        verbose=False,
    )
    private_key = CliReader(private_key_file)
    public_key = CliReader(public_key_file)
    message = CliReader(message_file)
    service.decrypt_public(
        private_key=private_key,
        passphrase=key_passphrase,
        public_key=public_key,
        message=message,
    )


@cli.command(aliases=["ds"])  # pyright: ignore[reportAny]
@click.argument("key_file", type=CliTypes.IN_PATH)
@click.argument("message_file", type=CliTypes.IN_PATH)
@CliOptions.text
@CliOptions.key_passphrase
@CliOptions.key_encoding
@CliOptions.data_encoding
@CliOptions.compression
@CliOptions.output_file
def decrypt_secret_cmd(
    key_file: Path,
    message_file: Path,
    text: bool,
    key_passphrase: str | None,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None:
    """Decrypt message (secret)."""
    writer = CliWriter(output_file)
    service = EncryptionService(
        text_mode=text,
        key_encoding=key_encoding,
        data_encoding=data_encoding,
        compression=compression,
        formatter=None,
        writer=writer,
        verbose=False,
    )
    key = CliReader(key_file)
    message = CliReader(message_file)
    service.decrypt_secret(key=key, passphrase=key_passphrase, message=message)


@cli.command(aliases=["dp"])  # pyright: ignore[reportAny]
@click.argument("password_file", type=CliTypes.IN_PATH)
@click.argument("message_file", type=CliTypes.IN_PATH)
@CliOptions.text
@CliOptions.kdf_profile
@CliOptions.data_encoding
@CliOptions.compression
@CliOptions.output_file
def decrypt_password_cmd(
    password_file: Path,
    message_file: Path,
    text: bool,
    kdf_profile: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None:
    """Decrypt message (password)."""
    writer = CliWriter(output_file)
    service = EncryptionService(
        text_mode=text,
        key_encoding="binary",
        data_encoding=data_encoding,
        compression=compression,
        formatter=None,
        writer=writer,
        verbose=False,
    )
    pw = CliReader(password_file)
    message = CliReader(message_file)
    service.decrypt_password(password=pw, message=message, kdf_profile=kdf_profile)


@cli.command()  # pyright: ignore[reportAny]
@click.argument("in_encoding", type=CliTypes.ENCODING, metavar="IN_ENCODING")
@click.argument("out_encoding", type=CliTypes.ENCODING, metavar="OUT_ENCODING")
@click.argument("file", type=CliTypes.IN_PATH)
@CliOptions.output_file
@CliOptions.group_len
@CliOptions.line_len
@CliOptions.padding
@CliOptions.verbose
def encode_cmd(
    in_encoding: str,
    out_encoding: str,
    file: Path,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None:
    """Encode file.

    See `soda encodings` for available encodings.
    """
    writer = CliWriter(output_file)
    formatter = FixedFormatter(group_len, line_len, padding)
    service = EncodingService(
        in_encoding=in_encoding,
        out_encoding=out_encoding,
        formatter=formatter,
        writer=writer,
        verbose=verbose,
    )
    data = CliReader(file)
    service.encode(data)


@cli.command(aliases=["ga"])  # pyright: ignore[reportAny]
@click.argument("key_file", type=CliTypes.IN_PATH)
def google_auth_cmd(key_file: Path) -> None:
    """Google Authenticator TOTP.

    Key must be Base32-encoded.

    When importing the key into Google Authenticator, strip the trailing '=' characters.
    """
    key = CliReader(key_file)
    totp = GoogleAuthenticator(key)
    click.echo(f"{totp.get_code()} (expires in {totp.get_remaining_seconds()}s)")


@cli.command()  # pyright: ignore[reportAny]
def encodings_cmd() -> None:
    """List supported encodings."""
    help_text = """
    base10 (Decimal)
    base26 (Latin)
    base31 (Cyrillic)
    base32 (RFC 4648)
    base36 (Latin with digits)
    base64 (RFC 4648)
    base94 (ASCII printable)
    binary (Raw bytes)

    Use binary or base64 for files larger than 1 MiB.
    """
    click.echo(help_text)


@cli.command()  # pyright: ignore[reportAny]
def compression_cmd() -> None:
    """List supported compression libs."""
    help_text = """
    brotli (Brotli, best ratio, default)
    zstd (Zstandard, fast, good ratio)
    zlib (Deflate, used by gzip)
    bz2 (Bzip2, used in tar.bz2)
    lzma (LZMA, good ratio on large data)
    raw (No compression, improves security)
    """
    click.echo(help_text)


@cli.command()  # pyright: ignore[reportAny]
def kdf_profiles_cmd() -> None:
    """List supported KDF profiles."""
    help_text = """
    interactive (64 MiB, 2 passes)
    moderate (256 MiB, 3 passes)
    sensitive (1 GiB, 4 passes)
    """
    click.echo(help_text)


if __name__ == "__main__":
    cli()
