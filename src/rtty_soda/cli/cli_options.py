from pathlib import Path
from typing import TYPE_CHECKING

import click

if TYPE_CHECKING:
    from click.decorators import FC

__all__ = ["CliOptions", "out_path"]

out_path = click.Path(
    file_okay=True, dir_okay=False, writable=True, allow_dash=True, path_type=Path
)


class CliOptions:
    @staticmethod
    def compression(function: FC) -> FC:
        return click.option(
            "--compression",
            "-c",
            default="brotli",
            show_default=True,
            envvar="SODA_COMPRESSION",
        )(function)

    @staticmethod
    def data_encoding(function: FC) -> FC:
        return click.option(
            "--data-encoding",
            "-e",
            default="base64",
            show_default=True,
            envvar="SODA_DATA_ENCODING",
        )(function)

    @staticmethod
    def key_encoding(function: FC) -> FC:
        return click.option(
            "--key-encoding",
            default="base64",
            show_default=True,
            envvar="SODA_KEY_ENCODING",
        )(function)

    @staticmethod
    def short_key_encoding(function: FC) -> FC:
        return click.option(
            "--encoding",
            "-e",
            default="base64",
            show_default=True,
            envvar="SODA_KEY_ENCODING",
        )(function)

    @staticmethod
    def kdf_profile(function: FC) -> FC:
        return click.option(
            "--kdf-profile",
            "-p",
            default="sensitive",
            show_default=True,
            envvar="SODA_KDF_PROFILE",
        )(function)

    @staticmethod
    def short_kdf_profile(function: FC) -> FC:
        return click.option(
            "--profile",
            "-p",
            default="sensitive",
            show_default=True,
            envvar="SODA_KDF_PROFILE",
        )(function)

    @staticmethod
    def verbose(function: FC) -> FC:
        return click.option(
            "--verbose",
            "-v",
            is_flag=True,
            envvar="SODA_VERBOSE",
            help="Show verbose output.",
        )(function)

    @staticmethod
    def text(function: FC) -> FC:
        return click.option(
            "--text",
            "-t",
            is_flag=True,
            envvar="SODA_TEXT",
            help="Treat message as text (binary if not specified).",
        )(function)

    @staticmethod
    def group_len(function: FC) -> FC:
        return click.option(
            "--group-len", default=0, show_default=True, envvar="SODA_GROUP_LEN"
        )(function)

    @staticmethod
    def line_len(function: FC) -> FC:
        return click.option(
            "--line-len", default=80, show_default=True, envvar="SODA_LINE_LEN"
        )(function)

    @staticmethod
    def output_file(function: FC) -> FC:
        return click.option(
            "--output-file", "-o", type=out_path, help="Write output to file."
        )(function)

    @staticmethod
    def padding(function: FC) -> FC:
        return click.option(
            "--padding", default=0, show_default=True, envvar="SODA_PADDING"
        )(function)
