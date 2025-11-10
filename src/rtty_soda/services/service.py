from typing import TYPE_CHECKING, NamedTuple

from rtty_soda.encoders import Encoder, encode_str
from rtty_soda.formatters import remove_whitespace

if TYPE_CHECKING:
    from rtty_soda.formatters import Formatter
    from rtty_soda.interfaces import Reader, Writer

__all__ = ["FormattedOutput", "Service"]


class FormattedOutput(NamedTuple):
    data: bytes
    chars: int
    groups: int


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

    def format_data(self, data: bytes, encoder: Encoder | None) -> FormattedOutput:
        chars = 0
        groups = 0
        if encoder is not None and self.formatter is not None:
            data_str = encoder.encode(data)
            chars = len(data_str)
            data_str, groups = self.formatter.format(data_str)
            data = encode_str(data_str)

        return FormattedOutput(data, chars, groups)

    def write_output(self, data: bytes, encoder: Encoder | None) -> None:
        buff = self.format_data(data, encoder)
        self.writer.write_bytes(buff.data)
        if self.verbose:
            self.writer.write_diag(f"Length: {buff.chars}")
            self.writer.write_diag(f"Groups: {buff.groups}")
