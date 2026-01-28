from pathlib import Path
from typing import TYPE_CHECKING

import click

from rtty_soda.archivers import ARCHIVERS
from rtty_soda.cryptography.kdf import KDF_PROFILES
from rtty_soda.encoders import ENCODERS

if TYPE_CHECKING:
    from click import ParamType

__all__ = ["CliTypes"]


class CliTypes:
    IN_PATH: ParamType = click.Path(
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        allow_dash=True,
        path_type=Path,
    )

    OUT_PATH: ParamType = click.Path(
        file_okay=True, dir_okay=False, writable=True, allow_dash=True, path_type=Path
    )

    ENCODING: ParamType = click.Choice(ENCODERS.keys(), case_sensitive=False)
    COMPRESSION: ParamType = click.Choice(ARCHIVERS.keys(), case_sensitive=False)
    KDF_PROFILE: ParamType = click.Choice(KDF_PROFILES.keys(), case_sensitive=False)
