from pathlib import Path

import click
from click_aliases import ClickAliasedGroup
from nacl.public import PrivateKey, PublicKey

from rtty_soda.archivers import ARCHIVERS, UNARCHIVERS
from rtty_soda.cli_io import (
    print_stats,
    read_bytes,
    read_ciphertext_bytes,
    read_clean_bytes,
    read_plaintext_bytes,
    write_output,
)
from rtty_soda.cryptography import public, secret
from rtty_soda.cryptography.kdf import KDF_PROFILES, kdf
from rtty_soda.encoders import ENCODERS, RawEncoder

in_path = click.Path(
    exists=True,
    file_okay=True,
    dir_okay=False,
    readable=True,
    allow_dash=True,
    path_type=Path,
)

out_path = click.Path(
    file_okay=True, dir_okay=False, writable=True, allow_dash=True, path_type=Path
)

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


@click.group(cls=ClickAliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.version_option(package_name="rtty-soda")
def cli() -> None:
    pass


@cli.command()
@click.option("--encoding", "-e", default="base64", show_default=True)
def genkey_cmd(encoding: str) -> None:
    """Generate Private Key.

    Encoding: base26 | base36 | base64 | base94
    """
    enc = ENCODERS[encoding]
    key = PrivateKey.generate()
    click.echo(key.encode(enc))


@cli.command()
@click.argument("private_key_file", type=in_path)
@click.option("--encoding", "-e", default="base64", show_default=True)
def pubkey_cmd(private_key_file: Path, encoding: str) -> None:
    """Get Public Key.

    Encoding: base26 | base36 | base64 | base94
    """
    enc = ENCODERS[encoding]
    key = read_clean_bytes(private_key_file)
    priv = PrivateKey(key, enc)
    click.echo(priv.public_key.encode(enc))


@cli.command()
@click.argument("password_file", type=in_path)
@click.option("--encoding", "-e", default="base64", show_default=True)
@click.option("--profile", "-p", default="sensitive", show_default=True)
def kdf_cmd(password_file: Path, encoding: str, profile: str) -> None:
    """Key Derivation Function.

    Encoding: base26 | base36 | base64 | base94

    Profile: interactive | moderate | sensitive
    """
    enc = ENCODERS[encoding]
    prof = KDF_PROFILES[profile]
    pw = read_bytes(password_file)
    key = kdf(pw, prof, enc)
    click.echo(key)


@cli.command(aliases=["e"])
@click.argument("private_key_file", type=in_path)
@click.argument("public_key_file", type=in_path)
@click.argument("message_file", type=in_path)
@click.option("--key-encoding", default="base64", show_default=True)
@click.option("--data-encoding", "-e", default="base64", show_default=True)
@click.option("--compression", "-c", default="zlib", show_default=True)
@click.option("--output-file", "-o", type=out_path, help="(Optional)")
def encrypt_public_cmd(  # noqa: PLR0913
    private_key_file: Path,
    public_key_file: Path,
    message_file: Path,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None:
    """Encrypt Message (Public).

    Encoding: base26 | base36 | base64 | base94 | binary

    Compression: zlib | bz2 | lzma | raw
    """
    key_enc = ENCODERS[key_encoding]
    data_enc = ENCODERS[data_encoding]
    archiver = ARCHIVERS[compression]
    priv_bytes = read_clean_bytes(private_key_file)
    priv = PrivateKey(priv_bytes, key_enc)
    pub_bytes = read_clean_bytes(public_key_file)
    pub = PublicKey(pub_bytes, key_enc)
    data = stats = read_plaintext_bytes(message_file, data_enc)
    data = archiver(data)
    data = public.encrypt(private=priv, public=pub, data=data, out_enc=data_enc)
    write_output(output_file, data, data_enc)
    print_stats(stats, data)


@cli.command(aliases=["es"])
@click.argument("key_file", type=in_path)
@click.argument("message_file", type=in_path)
@click.option("--key-encoding", default="base64", show_default=True)
@click.option("--data-encoding", "-e", default="base64", show_default=True)
@click.option("--compression", "-c", default="zlib", show_default=True)
@click.option("--output-file", "-o", type=out_path, help="(Optional)")
def encrypt_secret_cmd(  # noqa: PLR0913
    key_file: Path,
    message_file: Path,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None:
    """Encrypt Message (Secret).

    Encoding: base26 | base36 | base64 | base94 | binary

    Compression: zlib | bz2 | lzma | raw
    """
    key_enc = ENCODERS[key_encoding]
    data_enc = ENCODERS[data_encoding]
    archiver = ARCHIVERS[compression]
    key = read_clean_bytes(key_file)
    data = stats = read_plaintext_bytes(message_file, data_enc)
    data = archiver(data)
    data = secret.encrypt(key=key, data=data, key_enc=key_enc, out_enc=data_enc)
    write_output(output_file, data, data_enc)
    print_stats(stats, data)


@cli.command(aliases=["ep"])
@click.argument("password_file", type=in_path)
@click.argument("message_file", type=in_path)
@click.option("--kdf-profile", "-p", default="sensitive", show_default=True)
@click.option("--data-encoding", "-e", default="base64", show_default=True)
@click.option("--compression", "-c", default="zlib", show_default=True)
@click.option("--output-file", "-o", type=out_path, help="(Optional)")
def encrypt_password_cmd(  # noqa: PLR0913
    password_file: Path,
    message_file: Path,
    kdf_profile: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None:
    """Encrypt Message (Password).

    KDF profile: interactive | moderate | sensitive

    Encoding: base26 | base36 | base64 | base94 | binary

    Compression: zlib | bz2 | lzma | raw
    """
    prof = KDF_PROFILES[kdf_profile]
    data_enc = ENCODERS[data_encoding]
    archiver = ARCHIVERS[compression]
    pw = read_bytes(password_file)
    key = kdf(pw, prof, RawEncoder)
    data = stats = read_plaintext_bytes(message_file, data_enc)
    data = archiver(data)
    data = secret.encrypt(key=key, data=data, key_enc=RawEncoder, out_enc=data_enc)
    write_output(output_file, data, data_enc)
    print_stats(stats, data)


@cli.command(aliases=["d"])
@click.argument("private_key_file", type=in_path)
@click.argument("public_key_file", type=in_path)
@click.argument("message_file", type=in_path)
@click.option("--key-encoding", default="base64", show_default=True)
@click.option("--data-encoding", "-e", default="base64", show_default=True)
@click.option("--compression", "-c", default="zlib", show_default=True)
@click.option("--output-file", "-o", type=out_path, help="(Optional)")
def decrypt_public_cmd(  # noqa: PLR0913
    private_key_file: Path,
    public_key_file: Path,
    message_file: Path,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None:
    """Decrypt Message (Public).

    Encoding: base26 | base36 | base64 | base94 | binary

    Compression: zlib | bz2 | lzma | raw
    """
    key_enc = ENCODERS[key_encoding]
    data_enc = ENCODERS[data_encoding]
    unarchiver = UNARCHIVERS[compression]
    priv_bytes = read_clean_bytes(private_key_file)
    priv = PrivateKey(priv_bytes, key_enc)
    pub_bytes = read_clean_bytes(public_key_file)
    pub = PublicKey(pub_bytes, key_enc)
    data = stats = read_ciphertext_bytes(message_file, data_enc)
    data = public.decrypt(priv, pub, data, data_enc)
    data = unarchiver(data)
    write_output(output_file, data, data_enc)
    print_stats(data, stats)


@cli.command(aliases=["ds"])
@click.argument("key_file", type=in_path)
@click.argument("message_file", type=in_path)
@click.option("--key-encoding", default="base64", show_default=True)
@click.option("--data-encoding", "-e", default="base64", show_default=True)
@click.option("--compression", "-c", default="zlib", show_default=True)
@click.option("--output-file", "-o", type=out_path, help="(Optional)")
def decrypt_secret_cmd(  # noqa: PLR0913
    key_file: Path,
    message_file: Path,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None:
    """Decrypt Message (Secret).

    Encoding: base26 | base36 | base64 | base94 | binary

    Compression: zlib | bz2 | lzma | raw
    """
    key_enc = ENCODERS[key_encoding]
    data_enc = ENCODERS[data_encoding]
    unarchiver = UNARCHIVERS[compression]
    key = read_clean_bytes(key_file)
    data = stats = read_ciphertext_bytes(message_file, data_enc)
    data = secret.decrypt(key, data, key_enc, data_enc)
    data = unarchiver(data)
    write_output(output_file, data, data_enc)
    print_stats(data, stats)


@cli.command(aliases=["dp"])
@click.argument("password_file", type=in_path)
@click.argument("message_file", type=in_path)
@click.option("--kdf-profile", "-p", default="sensitive", show_default=True)
@click.option("--data-encoding", "-e", default="base64", show_default=True)
@click.option("--compression", "-c", default="zlib", show_default=True)
@click.option("--output-file", "-o", type=out_path, help="(Optional)")
def decrypt_password_cmd(  # noqa: PLR0913
    password_file: Path,
    message_file: Path,
    kdf_profile: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None:
    """Decrypt Message (Password).

    KDF profile: interactive | moderate | sensitive

    Encoding: base26 | base36 | base64 | base94 | binary

    Compression: zlib | bz2 | lzma | raw
    """
    prof = KDF_PROFILES[kdf_profile]
    data_enc = ENCODERS[data_encoding]
    unarchiver = UNARCHIVERS[compression]
    pw = read_bytes(password_file)
    key = kdf(pw, prof, RawEncoder)
    data = stats = read_ciphertext_bytes(message_file, data_enc)
    data = secret.decrypt(key, data, RawEncoder, data_enc)
    data = unarchiver(data)
    write_output(output_file, data, data_enc)
    print_stats(data, stats)


@cli.command()
@click.argument("in_encoding")
@click.argument("out_encoding")
@click.argument("file", type=in_path)
@click.option("--output-file", "-o", type=out_path, help="(Optional)")
def encode_cmd(
    in_encoding: str, out_encoding: str, file: Path, output_file: Path | None
) -> None:
    """Encode File.

    Encoding: base26 | base36 | base64 | base94 | binary
    """
    in_enc = ENCODERS[in_encoding]
    out_enc = ENCODERS[out_encoding]
    data = read_ciphertext_bytes(file, in_enc)
    data = in_enc.decode(data)
    data = out_enc.encode(data)
    write_output(output_file, data, out_enc)


if __name__ == "__main__":
    cli()
