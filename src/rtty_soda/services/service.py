import string
from typing import TYPE_CHECKING, NamedTuple

from rtty_soda.encoders import Encoder, encode_str

if TYPE_CHECKING:
    from rtty_soda.formatters import Formatter
    from rtty_soda.interfaces import Reader, Writer

__all__ = ["FormattedData", "Service"]


class FormattedData(NamedTuple):
    data: bytes
    length: int  # data len in chars or in bytes
    groups: int  # number of groups


class Service:
    def __init__(
        self, formatter: Formatter | None, writer: Writer, verbose: bool
    ) -> None:
        self.formatter = formatter
        self.writer = writer
        self.verbose = verbose

    @staticmethod
    def remove_whitespace(data: str) -> str:
        trans = str.maketrans("", "", string.whitespace)
        return data.translate(trans)

    def read_input(self, source: Reader, encoder: Encoder | None) -> bytes:
        """Read key or ciphertext."""
        if encoder is None:
            return source.read_bytes()

        data = source.read_str()
        data = self.remove_whitespace(data)
        return encoder.decode(data)

    def format_data(self, data: bytes, encoder: Encoder | None) -> FormattedData:
        """Format key or ciphertext."""
        if encoder is None or self.formatter is None:
            return FormattedData(data, len(data), 1)

        data_str = encoder.encode(data)
        formatted = self.formatter.format(data_str)
        data_bytes = encode_str(formatted.text)
        return FormattedData(data_bytes, len(data_str), formatted.groups)

    def write_output(self, data: bytes, encoder: Encoder | None) -> None:
        """Write key or ciphertext."""
        buff = self.format_data(data, encoder)
        self.writer.write_bytes(buff.data)
        if self.verbose:
            self.writer.write_diag(f"Length: {buff.length}")
            self.writer.write_diag(f"Groups: {buff.groups}")
