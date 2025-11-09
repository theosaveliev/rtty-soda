from typing import TYPE_CHECKING, BinaryIO, TextIO, cast

from rtty_soda.interfaces import Reader

if TYPE_CHECKING:
    from pathlib import Path

import click

__all__ = ["CliReader"]


class CliReader(Reader):
    def __init__(self, source: Path) -> None:
        self.source = source

    def read_str(self) -> str:
        with click.open_file(
            self.source, mode="rt", encoding="utf-8", errors="strict"
        ) as fd:
            return cast("TextIO", fd).read()

    def read_bytes(self) -> bytes:
        with click.open_file(self.source, mode="rb") as fd:
            return cast("BinaryIO", fd).read()
