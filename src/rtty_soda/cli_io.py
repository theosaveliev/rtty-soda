import random
import re
import string
from pathlib import Path
from typing import TextIO, cast

import click

from rtty_soda.encoders import Encoder, RawEncoder, encode_str

__all__ = [
    "print_stats",
    "read_bytes",
    "read_ciphertext_bytes",
    "read_clean_bytes",
    "read_plaintext_bytes",
    "read_str",
    "remove_whitespace",
    "write_bytes_atomic",
    "write_output",
]


def read_str(source: Path) -> str:
    with click.open_file(source, mode="rt", encoding="utf-8", errors="strict") as fd:
        return cast("TextIO", fd).read().strip()


def read_bytes(source: Path) -> bytes:
    return encode_str(read_str(source))


def remove_whitespace(data: str) -> str:
    return re.sub(r"\s", "", data)


def read_clean_bytes(source: Path) -> bytes:
    data = read_str(source)
    data = remove_whitespace(data)
    return encode_str(data)


def read_plaintext_bytes(source: Path, in_enc: Encoder) -> bytes:
    if in_enc == RawEncoder:
        return source.read_bytes()

    return read_bytes(source)


def read_ciphertext_bytes(source: Path, in_enc: Encoder) -> bytes:
    if in_enc == RawEncoder:
        return source.read_bytes()

    return read_clean_bytes(source)


def write_bytes_atomic(target: Path, data: bytes) -> None:
    temp_name = "".join(random.choices(string.ascii_lowercase, k=10))  # noqa: S311
    temp_path = target.parent / temp_name
    temp_path.write_bytes(data)
    temp_path.replace(target)


def write_output(target: Path | None, data: bytes, out_enc: Encoder) -> None:
    if target is None or target.stem == "-":
        if out_enc == RawEncoder:
            click.confirm(
                "Print binary output to the terminal?", default=False, abort=True
            )

        click.echo()
        click.echo(data)
        click.echo()
    else:
        if target.exists():
            click.confirm(
                f"Overwrite the output file? ({target})", default=False, abort=True
            )

        write_bytes_atomic(target, data)


def print_stats(plaintext: bytes, ciphertext: bytes) -> None:
    click.echo(f"Plaintext: {len(plaintext)}", err=True)
    click.echo(f"Ciphertext: {len(ciphertext)}", err=True)
    overhead = len(ciphertext) / len(plaintext)
    click.echo(f"Overhead: {overhead:.3f}", err=True)
