import itertools
import math
from typing import NamedTuple, Protocol

__all__ = ["FixedFormatter", "FormattedText", "Formatter"]


class FormattedText(NamedTuple):
    text: str
    groups: int


class Formatter(Protocol):
    def format(self, text: str) -> FormattedText: ...


class FixedFormatter(Formatter):
    def __init__(self, group_len: int, line_len: int, pad_count: int) -> None:
        self.group_len = group_len
        self.line_len = line_len
        self.pad_count = pad_count

    def format(self, text: str) -> FormattedText:
        groups = 1

        if 0 < self.group_len < self.line_len:
            text, groups = self.split_groups(text)

        if self.pad_count > 0:
            text = self.pad_newlines(text)

        return FormattedText(text, groups)

    def split_groups(self, data: str) -> FormattedText:
        step = self.group_len
        gpl = self.line_len // (step + 1)
        groups = (data[i : i + step] for i in range(0, len(data), step))
        groups_len = math.ceil(len(data) / step)
        lines = (" ".join(ln) for ln in itertools.batched(groups, gpl, strict=False))
        return FormattedText("\n".join(lines), groups_len)

    def pad_newlines(self, text: str) -> str:
        padding = "\n" * self.pad_count
        return padding + text.strip() + "\n" + padding
