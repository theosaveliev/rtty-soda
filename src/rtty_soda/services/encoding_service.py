from typing import TYPE_CHECKING

from rtty_soda.encoders import ENCODERS

from .service import Service

if TYPE_CHECKING:
    from rtty_soda.formatters import Formatter
    from rtty_soda.interfaces import Reader, Writer

__all__ = ["EncodingService"]


class EncodingService(Service):
    def __init__(
        self,
        in_encoding: str,
        out_encoding: str,
        formatter: Formatter,
        writer: Writer,
        verbose: bool,
    ) -> None:
        super().__init__(formatter, writer, verbose)
        self.in_encoder = ENCODERS.get(in_encoding)
        self.out_encoder = ENCODERS.get(out_encoding)

    def encode(self, data: Reader) -> None:
        buff = self.read_input(data, self.in_encoder)
        self.write_output(buff, self.out_encoder)
