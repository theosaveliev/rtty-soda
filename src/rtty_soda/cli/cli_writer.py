import random
import string
from typing import TYPE_CHECKING

from rtty_soda.interfaces import Writer

if TYPE_CHECKING:
    from pathlib import Path

import click

__all__ = ["CliWriter"]


class CliWriter(Writer):
    def __init__(self, target: Path | None) -> None:
        self.target = target

    @staticmethod
    def write_bytes_atomic(target: Path, data: bytes) -> None:
        temp_name = "".join(random.choices(string.ascii_lowercase, k=10))  # noqa: S311
        temp_path = target.parent / temp_name
        temp_path.write_bytes(data)
        temp_path.replace(target)

    def write_bytes(self, data: bytes) -> None:
        if self.target is None or self.target.stem == "-":
            add_nl = not data.endswith(b"\n")
            click.echo(data, nl=add_nl)
        else:
            if self.target.exists():
                click.confirm(
                    f"Overwrite the output file? ({self.target})",
                    default=False,
                    abort=True,
                )

            self.write_bytes_atomic(self.target, data)

    def write_diag(self, message: str) -> None:
        click.echo(message, err=True)
