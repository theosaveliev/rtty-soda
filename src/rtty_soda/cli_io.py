import random
import re
import string
from typing import TYPE_CHECKING, TextIO, cast

if TYPE_CHECKING:
    from pathlib import Path

import click

from rtty_soda.encoders import Encoder, decode_bytes, encode_str

__all__ = [
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


def read_bytes(source: Path, is_binary: bool) -> bytes:
    if is_binary:
        return source.read_bytes()

    return read_encoded_stripped(source)


def read_key_bytes(source: Path, is_binary: bool, encoder: Encoder) -> bytes:
    key = read_bytes(source, is_binary)
    return encoder.decode(key)


def read_password_bytes(source: Path) -> bytes:
    return encode_str(read_str(source).strip())


def write_bytes_atomic(target: Path, data: bytes) -> None:
    temp_name = "".join(random.choices(string.ascii_lowercase, k=10))  # noqa: S311
    temp_path = target.parent / temp_name
    temp_path.write_bytes(data)
    temp_path.replace(target)


def split_groups(data: str, group_len: int, line_len: int) -> str:
    step = group_len if group_len > 0 else line_len - 1
    groups = (data[i : i + step] for i in range(0, len(data), step))
    result: list[str] = []
    line: list[str] = []
    i = 0
    gpl = line_len // (step + 1)
    for group in groups:
        line.append(group)
        i += 1
        if i == gpl:
            result.append(" ".join(line))
            i = 0
            line = []

    if line:
        result.append(" ".join(line))

    return "\n".join(result)


def pad_newlines(data: bytes, count: int) -> bytes:
    padding = b"\n" * count
    return padding + data + padding


def write_output(
    target: Path | None,
    data: bytes,
    is_binary: bool,
    group_len: int,
    line_len: int,
    padding: int,
) -> None:
    if not is_binary and (group_len > 0 or line_len > 0):
        text = decode_bytes(data)
        text = split_groups(text, group_len, line_len)
        data = encode_str(text)

    if padding > 0:
        data = pad_newlines(data, padding)

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
