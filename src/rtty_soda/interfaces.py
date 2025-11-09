from typing import Protocol

__all__ = ["Reader", "Writer"]


class Reader(Protocol):
    """Reads data source."""

    def read_str(self) -> str: ...

    def read_bytes(self) -> bytes: ...


class Writer(Protocol):
    """Outputs data and prints diagnostics."""

    def write_bytes(self, data: bytes) -> None: ...

    def write_diag(self, message: str) -> None: ...
