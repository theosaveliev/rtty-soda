import random
import re
import string
from typing import TYPE_CHECKING, TextIO, cast

if TYPE_CHECKING:
    from pathlib import Path

import click

from rtty_soda.encoders import Encoder, decode_bytes, encode_str

__all__ = [
    "format_output",
    "pad_newlines",
    "print_stats",
    "read_bytes",
    "read_encoded_stripped",
    "read_key_bytes",
    "read_password_bytes",
    "read_str",
    "remove_whitespace",
    "split_groups",
    "write_bytes_atomic",
    "write_output",
]


def read_str(source: Path) -> str:
    with click.open_file(source, mode="rt", encoding="utf-8", errors="strict") as fd:
        return cast("TextIO", fd).read()


def remove_whitespace(data: str) -> str:
    return re.sub(r"\s", "", data)


def read_encoded_stripped(source: Path) -> bytes:
    data = read_str(source)
    data = remove_whitespace(data)
    return encode_str(data)


def read_bytes(source: Path, encoder: Encoder) -> bytes:
    if encoder.is_binary:
        return source.read_bytes()

    return read_encoded_stripped(source)


def read_key_bytes(source: Path, encoder: Encoder) -> bytes:
    key = read_bytes(source, encoder)
    return encoder.decode(key)


def read_password_bytes(source: Path) -> bytes:
    return encode_str(read_str(source).strip())


def write_bytes_atomic(target: Path, data: bytes) -> None:
    temp_name = "".join(random.choices(string.ascii_lowercase, k=10))  # noqa: S311
    temp_path = target.parent / temp_name
    temp_path.write_bytes(data)
    temp_path.replace(target)


def split_groups(data: str, group_len: int, line_len: int) -> tuple[str, int]:
    step, gpl = group_len, line_len // (group_len + 1)
    groups = [data[i : i + step] for i in range(0, len(data), step)]
    lines = [" ".join(groups[i : i + gpl]) for i in range(0, len(groups), gpl)]
    return "\n".join(lines), len(groups)


def pad_newlines(data: str, count: int) -> str:
    padding = "\n" * count
    return padding + data.strip() + "\n" + padding


def format_output(
    data: bytes, encoder: Encoder, group_len: int, line_len: int, padding: int
) -> tuple[bytes, int]:
    groups = 1
    if encoder.is_binary:
        return data, groups

    text = decode_bytes(data)
    if 0 < group_len < line_len:
        text, groups = split_groups(text, group_len, line_len)

    if padding > 0:
        text = pad_newlines(text, padding)

    return encode_str(text), groups


def write_output(target: Path | None, data: bytes) -> None:
    if target is None or target.stem == "-":
        add_nl = not data.endswith(b"\n")
        click.echo(data, nl=add_nl)
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
