from pathlib import Path

import click
from click_aliases import ClickAliasedGroup
from nacl.public import PrivateKey, PublicKey

from rtty_soda.archivers import ARCHIVERS, UNARCHIVERS
from rtty_soda.cli_io import (
    format_output,
    print_stats,
    read_bytes,
    read_key_bytes,
    read_password_bytes,
    write_output,
)
from rtty_soda.cryptography import public, secret
from rtty_soda.cryptography.kdf import KDF_PROFILES, kdf
from rtty_soda.encoders import ENCODERS

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


@cli.command()  # pyright: ignore[reportAny]
@click.option(
    "--encoding", "-e", default="base64", show_default=True, envvar="KEY_ENCODING"
)
@click.option("--output-file", "-o", type=out_path, help="Write output to file.")
@click.option("--group-len", default=0, show_default=True, envvar="GROUP_LEN")
@click.option("--line-len", default=80, show_default=True, envvar="LINE_LEN")
@click.option("--padding", default=0, show_default=True, envvar="PADDING")
@click.option(
    "--verbose", "-v", is_flag=True, envvar="VERBOSE", help="Show verbose output."
)
def genkey_cmd(
    encoding: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None:
    """Generate Private Key.

    Encoding: base26 | base31 | base36 | base64 | base94 | binary
    """
    enc = ENCODERS[encoding]

    key = bytes(PrivateKey.generate())
    key = enc.encode(key)

    formatted, groups = format_output(
        data=key, encoder=enc, group_len=group_len, line_len=line_len, padding=padding
    )
    write_output(target=output_file, data=formatted)

    if verbose:
        click.echo(f"Groups: {groups}", err=True)


@cli.command()  # pyright: ignore[reportAny]
@click.argument("private_key_file", type=in_path)
@click.option(
    "--encoding", "-e", default="base64", show_default=True, envvar="KEY_ENCODING"
)
@click.option("--output-file", "-o", type=out_path, help="Write output to file.")
@click.option("--group-len", default=0, show_default=True, envvar="GROUP_LEN")
@click.option("--line-len", default=80, show_default=True, envvar="LINE_LEN")
@click.option("--padding", default=0, show_default=True, envvar="PADDING")
@click.option(
    "--verbose", "-v", is_flag=True, envvar="VERBOSE", help="Show verbose output."
)
def pubkey_cmd(
    private_key_file: Path,
    encoding: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None:
    """Get Public Key.

    Encoding: base26 | base31 | base36 | base64 | base94 | binary
    """
    enc = ENCODERS[encoding]

    priv = read_key_bytes(source=private_key_file, encoder=enc)
    priv = PrivateKey(private_key=priv)
    pub = bytes(priv.public_key)
    pub = enc.encode(pub)

    formatted, groups = format_output(
        data=pub, encoder=enc, group_len=group_len, line_len=line_len, padding=padding
    )
    write_output(target=output_file, data=formatted)

    if verbose:
        click.echo(f"Groups: {groups}", err=True)


@cli.command()  # pyright: ignore[reportAny]
@click.argument("password_file", type=in_path)
@click.option(
    "--encoding", "-e", default="base64", show_default=True, envvar="KEY_ENCODING"
)
@click.option(
    "--profile", "-p", default="sensitive", show_default=True, envvar="KDF_PROFILE"
)
@click.option("--output-file", "-o", type=out_path, help="Write output to file.")
@click.option("--group-len", default=0, show_default=True, envvar="GROUP_LEN")
@click.option("--line-len", default=80, show_default=True, envvar="LINE_LEN")
@click.option("--padding", default=0, show_default=True, envvar="PADDING")
@click.option(
    "--verbose", "-v", is_flag=True, envvar="VERBOSE", help="Show verbose output."
)
def kdf_cmd(
    password_file: Path,
    encoding: str,
    profile: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None:
    """Key Derivation Function.

    Encoding: base26 | base31 | base36 | base64 | base94 | binary

    Profile: interactive | moderate | sensitive
    """
    enc = ENCODERS[encoding]
    prof = KDF_PROFILES[profile]

    pw = read_password_bytes(password_file)
    key = kdf(password=pw, profile=prof)
    key = enc.encode(key)

    formatted, groups = format_output(
        data=key, encoder=enc, group_len=group_len, line_len=line_len, padding=padding
    )
    write_output(target=output_file, data=formatted)

    if verbose:
        click.echo(f"Groups: {groups}", err=True)


@cli.command(aliases=["e"])  # pyright: ignore[reportAny]
@click.argument("private_key_file", type=in_path)
@click.argument("public_key_file", type=in_path)
@click.argument("message_file", type=in_path)
@click.option(
    "--key-encoding", default="base64", show_default=True, envvar="KEY_ENCODING"
)
@click.option(
    "--data-encoding", "-e", default="base64", show_default=True, envvar="DATA_ENCODING"
)
@click.option(
    "--compression", "-c", default="zstd", show_default=True, envvar="COMPRESSION"
)
@click.option("--output-file", "-o", type=out_path, help="Write output to file.")
@click.option("--group-len", default=0, show_default=True, envvar="GROUP_LEN")
@click.option("--line-len", default=80, show_default=True, envvar="LINE_LEN")
@click.option("--padding", default=0, show_default=True, envvar="PADDING")
@click.option(
    "--verbose", "-v", is_flag=True, envvar="VERBOSE", help="Show verbose output."
)
def encrypt_public_cmd(
    private_key_file: Path,
    public_key_file: Path,
    message_file: Path,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None:
    """Encrypt Message (Public).

    Encoding: base26 | base31 | base36 | base64 | base94 | binary

    Compression: zstd | zlib | bz2 | lzma | raw
    """
    key_enc = ENCODERS[key_encoding]
    data_enc = ENCODERS[data_encoding]
    archiver = ARCHIVERS[compression]

    priv = read_key_bytes(source=private_key_file, encoder=key_enc)
    priv = PrivateKey(private_key=priv)
    pub = read_key_bytes(source=public_key_file, encoder=key_enc)
    pub = PublicKey(public_key=pub)
    plaintext = message_file.read_bytes()
    data = archiver(plaintext)
    data = public.encrypt(private=priv, public=pub, data=data)
    ciphertext = data_enc.encode(data)

    formatted, groups = format_output(
        data=ciphertext,
        encoder=data_enc,
        group_len=group_len,
        line_len=line_len,
        padding=padding,
    )
    write_output(target=output_file, data=formatted)

    if verbose:
        print_stats(len(plaintext), len(ciphertext))
        click.echo(f"Groups: {groups}", err=True)


@cli.command(aliases=["es"])  # pyright: ignore[reportAny]
@click.argument("key_file", type=in_path)
@click.argument("message_file", type=in_path)
@click.option(
    "--key-encoding", default="base64", show_default=True, envvar="KEY_ENCODING"
)
@click.option(
    "--data-encoding", "-e", default="base64", show_default=True, envvar="DATA_ENCODING"
)
@click.option(
    "--compression", "-c", default="zstd", show_default=True, envvar="COMPRESSION"
)
@click.option("--output-file", "-o", type=out_path, help="Write output to file.")
@click.option("--group-len", default=0, show_default=True, envvar="GROUP_LEN")
@click.option("--line-len", default=80, show_default=True, envvar="LINE_LEN")
@click.option("--padding", default=0, show_default=True, envvar="PADDING")
@click.option(
    "--verbose", "-v", is_flag=True, envvar="VERBOSE", help="Show verbose output."
)
def encrypt_secret_cmd(
    key_file: Path,
    message_file: Path,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None:
    """Encrypt Message (Secret).

    Encoding: base26 | base31 | base36 | base64 | base94 | binary

    Compression: zstd | zlib | bz2 | lzma | raw
    """
    key_enc = ENCODERS[key_encoding]
    data_enc = ENCODERS[data_encoding]
    archiver = ARCHIVERS[compression]

    key = read_key_bytes(source=key_file, encoder=key_enc)
    plaintext = message_file.read_bytes()
    data = archiver(plaintext)
    data = secret.encrypt(key=key, data=data)
    ciphertext = data_enc.encode(data)

    formatted, groups = format_output(
        data=ciphertext,
        encoder=data_enc,
        group_len=group_len,
        line_len=line_len,
        padding=padding,
    )
    write_output(target=output_file, data=formatted)

    if verbose:
        print_stats(len(plaintext), len(ciphertext))
        click.echo(f"Groups: {groups}", err=True)


@cli.command(aliases=["ep"])  # pyright: ignore[reportAny]
@click.argument("password_file", type=in_path)
@click.argument("message_file", type=in_path)
@click.option(
    "--kdf-profile", "-p", default="sensitive", show_default=True, envvar="KDF_PROFILE"
)
@click.option(
    "--data-encoding", "-e", default="base64", show_default=True, envvar="DATA_ENCODING"
)
@click.option(
    "--compression", "-c", default="zstd", show_default=True, envvar="COMPRESSION"
)
@click.option("--output-file", "-o", type=out_path, help="Write output to file.")
@click.option("--group-len", default=0, show_default=True, envvar="GROUP_LEN")
@click.option("--line-len", default=80, show_default=True, envvar="LINE_LEN")
@click.option("--padding", default=0, show_default=True, envvar="PADDING")
@click.option(
    "--verbose", "-v", is_flag=True, envvar="VERBOSE", help="Show verbose output."
)
def encrypt_password_cmd(
    password_file: Path,
    message_file: Path,
    kdf_profile: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None:
    """Encrypt Message (Password).

    KDF profile: interactive | moderate | sensitive

    Encoding: base26 | base31 | base36 | base64 | base94 | binary

    Compression: zstd | zlib | bz2 | lzma | raw
    """
    prof = KDF_PROFILES[kdf_profile]
    data_enc = ENCODERS[data_encoding]
    archiver = ARCHIVERS[compression]

    pw = read_password_bytes(password_file)
    key = kdf(password=pw, profile=prof)
    plaintext = message_file.read_bytes()
    data = archiver(plaintext)
    data = secret.encrypt(key=key, data=data)
    ciphertext = data_enc.encode(data)

    formatted, groups = format_output(
        data=ciphertext,
        encoder=data_enc,
        group_len=group_len,
        line_len=line_len,
        padding=padding,
    )
    write_output(target=output_file, data=formatted)

    if verbose:
        print_stats(len(plaintext), len(ciphertext))
        click.echo(f"Groups: {groups}", err=True)


@cli.command(aliases=["d"])  # pyright: ignore[reportAny]
@click.argument("private_key_file", type=in_path)
@click.argument("public_key_file", type=in_path)
@click.argument("message_file", type=in_path)
@click.option(
    "--key-encoding", default="base64", show_default=True, envvar="KEY_ENCODING"
)
@click.option(
    "--data-encoding", "-e", default="base64", show_default=True, envvar="DATA_ENCODING"
)
@click.option(
    "--compression", "-c", default="zstd", show_default=True, envvar="COMPRESSION"
)
@click.option("--output-file", "-o", type=out_path, help="Write output to file.")
@click.option(
    "--verbose", "-v", is_flag=True, envvar="VERBOSE", help="Show verbose output."
)
def decrypt_public_cmd(
    private_key_file: Path,
    public_key_file: Path,
    message_file: Path,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
    verbose: bool,
) -> None:
    """Decrypt Message (Public).

    Encoding: base26 | base31 | base36 | base64 | base94 | binary

    Compression: zstd | zlib | bz2 | lzma | raw
    """
    key_enc = ENCODERS[key_encoding]
    data_enc = ENCODERS[data_encoding]
    unarchiver = UNARCHIVERS[compression]

    priv = read_key_bytes(source=private_key_file, encoder=key_enc)
    priv = PrivateKey(private_key=priv)
    pub = read_key_bytes(source=public_key_file, encoder=key_enc)
    pub = PublicKey(public_key=pub)
    ciphertext = read_bytes(source=message_file, encoder=data_enc)
    data = data_enc.decode(ciphertext)
    data = public.decrypt(private=priv, public=pub, data=data)
    plaintext = unarchiver(data)

    write_output(target=output_file, data=plaintext)

    if verbose:
        print_stats(len(plaintext), len(ciphertext))


@cli.command(aliases=["ds"])  # pyright: ignore[reportAny]
@click.argument("key_file", type=in_path)
@click.argument("message_file", type=in_path)
@click.option(
    "--key-encoding", default="base64", show_default=True, envvar="KEY_ENCODING"
)
@click.option(
    "--data-encoding", "-e", default="base64", show_default=True, envvar="DATA_ENCODING"
)
@click.option(
    "--compression", "-c", default="zstd", show_default=True, envvar="COMPRESSION"
)
@click.option("--output-file", "-o", type=out_path, help="Write output to file.")
@click.option(
    "--verbose", "-v", is_flag=True, envvar="VERBOSE", help="Show verbose output."
)
def decrypt_secret_cmd(
    key_file: Path,
    message_file: Path,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
    verbose: bool,
) -> None:
    """Decrypt Message (Secret).

    Encoding: base26 | base31 | base36 | base64 | base94 | binary

    Compression: zstd | zlib | bz2 | lzma | raw
    """
    key_enc = ENCODERS[key_encoding]
    data_enc = ENCODERS[data_encoding]
    unarchiver = UNARCHIVERS[compression]

    key = read_key_bytes(source=key_file, encoder=key_enc)
    ciphertext = read_bytes(source=message_file, encoder=data_enc)
    data = data_enc.decode(ciphertext)
    data = secret.decrypt(key=key, data=data)
    plaintext = unarchiver(data)

    write_output(target=output_file, data=plaintext)

    if verbose:
        print_stats(len(plaintext), len(ciphertext))


@cli.command(aliases=["dp"])  # pyright: ignore[reportAny]
@click.argument("password_file", type=in_path)
@click.argument("message_file", type=in_path)
@click.option(
    "--kdf-profile", "-p", default="sensitive", show_default=True, envvar="KDF_PROFILE"
)
@click.option(
    "--data-encoding", "-e", default="base64", show_default=True, envvar="DATA_ENCODING"
)
@click.option(
    "--compression", "-c", default="zstd", show_default=True, envvar="COMPRESSION"
)
@click.option("--output-file", "-o", type=out_path, help="Write output to file.")
@click.option(
    "--verbose", "-v", is_flag=True, envvar="VERBOSE", help="Show verbose output."
)
def decrypt_password_cmd(
    password_file: Path,
    message_file: Path,
    kdf_profile: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
    verbose: bool,
) -> None:
    """Decrypt Message (Password).

    KDF profile: interactive | moderate | sensitive

    Encoding: base26 | base31 | base36 | base64 | base94 | binary

    Compression: zstd | zlib | bz2 | lzma | raw
    """
    prof = KDF_PROFILES[kdf_profile]
    data_enc = ENCODERS[data_encoding]
    unarchiver = UNARCHIVERS[compression]

    pw = read_password_bytes(password_file)
    key = kdf(password=pw, profile=prof)
    ciphertext = read_bytes(source=message_file, encoder=data_enc)
    data = data_enc.decode(ciphertext)
    data = secret.decrypt(key=key, data=data)
    plaintext = unarchiver(data)

    write_output(target=output_file, data=plaintext)

    if verbose:
        print_stats(len(plaintext), len(ciphertext))


@cli.command()  # pyright: ignore[reportAny]
@click.argument("in_encoding")
@click.argument("out_encoding")
@click.argument("file", type=in_path)
@click.option("--output-file", "-o", type=out_path, help="Write output to file.")
@click.option("--group-len", default=0, show_default=True, envvar="GROUP_LEN")
@click.option("--line-len", default=80, show_default=True, envvar="LINE_LEN")
@click.option("--padding", default=0, show_default=True, envvar="PADDING")
@click.option(
    "--verbose", "-v", is_flag=True, envvar="VERBOSE", help="Show verbose output."
)
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
    """Encode File.

    Encoding: base26 | base31 | base36 | base64 | base94 | binary
    """
    in_enc = ENCODERS[in_encoding]
    out_enc = ENCODERS[out_encoding]

    data = read_bytes(source=file, encoder=in_enc)
    data = in_enc.decode(data)
    data = out_enc.encode(data)

    formatted, groups = format_output(
        data=data,
        encoder=out_enc,
        group_len=group_len,
        line_len=line_len,
        padding=padding,
    )
    write_output(target=output_file, data=formatted)

    if verbose:
        click.echo(f"Groups: {groups}", err=True)


if __name__ == "__main__":
    cli()
