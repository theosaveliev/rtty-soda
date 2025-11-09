from typing import TYPE_CHECKING

from rtty_soda.encoders import Encoder, encode_str
from rtty_soda.formatters import remove_whitespace

if TYPE_CHECKING:
    from rtty_soda.formatters import Formatter
    from rtty_soda.interfaces import Reader, Writer

__all__ = ["Service"]


class Service:
    def __init__(
        self, formatter: Formatter | None, writer: Writer, verbose: bool
    ) -> None:
        self.formatter = formatter
        self.writer = writer
        self.verbose = verbose

    @staticmethod
    def read_input(source: Reader, encoder: Encoder | None) -> bytes:
        if encoder is None:
            return source.read_bytes()

        data = source.read_str()
        data = remove_whitespace(data)
        return encoder.decode(data)

    def format_data(self, data: bytes, encoder: Encoder | None) -> tuple[bytes, int]:
        groups = 1
        if encoder is not None and self.formatter is not None:
            data_str = encoder.encode(data)
            data_str, groups = self.formatter.format(data_str)
            data = encode_str(data_str)

        return data, groups

    def write_output(self, data: bytes, encoder: Encoder | None) -> None:
        data, groups = self.format_data(data, encoder)
        self.writer.write_bytes(data)
        if self.verbose:
            self.writer.write_diag(f"Groups: {groups}")
