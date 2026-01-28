from typing import TYPE_CHECKING

import click

from .cli_types import CliTypes

if TYPE_CHECKING:
    from click.decorators import FC

__all__ = ["CliOptions"]


class CliOptions:
    @staticmethod
    def compression(function: FC) -> FC:
        return click.option(
            "--compression",
            "-c",
            type=CliTypes.COMPRESSION,
            default="brotli",
            show_default=True,
            metavar="COMPRESSION",
            envvar="SODA_COMPRESSION",
            help="See `soda compression`.",
        )(function)

    @staticmethod
    def data_encoding(function: FC) -> FC:
        return click.option(
            "--data-encoding",
            "-e",
            type=CliTypes.ENCODING,
            default="base64",
            show_default=True,
            metavar="ENCODING",
            envvar="SODA_DATA_ENCODING",
            help="See `soda encodings`.",
        )(function)

    @staticmethod
    def key_encoding(function: FC) -> FC:
        return click.option(
            "--key-encoding",
            type=CliTypes.ENCODING,
            default="base64",
            show_default=True,
            metavar="ENCODING",
            envvar="SODA_KEY_ENCODING",
            help="See `soda encodings`.",
        )(function)

    @staticmethod
    def short_key_encoding(function: FC) -> FC:
        return click.option(
            "--encoding",
            "-e",
            type=CliTypes.ENCODING,
            default="base64",
            show_default=True,
            metavar="ENCODING",
            envvar="SODA_KEY_ENCODING",
            help="See `soda encodings`.",
        )(function)

    @staticmethod
    def kdf_profile(function: FC) -> FC:
        return click.option(
            "--kdf-profile",
            "-p",
            type=CliTypes.KDF_PROFILE,
            default="sensitive",
            show_default=True,
            metavar="PROFILE",
            envvar="SODA_KDF_PROFILE",
            help="See `soda kdf-profiles`.",
        )(function)

    @staticmethod
    def short_kdf_profile(function: FC) -> FC:
        return click.option(
            "--profile",
            "-p",
            type=CliTypes.KDF_PROFILE,
            default="sensitive",
            show_default=True,
            metavar="PROFILE",
            envvar="SODA_KDF_PROFILE",
            help="See `soda kdf-profiles`.",
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
            "--group-len", "-g", default=0, show_default=True, envvar="SODA_GROUP_LEN"
        )(function)

    @staticmethod
    def line_len(function: FC) -> FC:
        return click.option(
            "--line-len", default=80, show_default=True, envvar="SODA_LINE_LEN"
        )(function)

    @staticmethod
    def output_file(function: FC) -> FC:
        return click.option(
            "--output-file", "-o", type=CliTypes.OUT_PATH, help="Write output to file."
        )(function)

    @staticmethod
    def padding(function: FC) -> FC:
        return click.option(
            "--padding", default=0, show_default=True, envvar="SODA_PADDING"
        )(function)
