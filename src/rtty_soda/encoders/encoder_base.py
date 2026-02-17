import math
from typing import ClassVar

from gmpy2 import mpz

__all__ = ["EncoderBase"]


class EncoderBase:
    alphabet: ClassVar[str]
    base: ClassVar[mpz]
    zero: ClassVar[str]
    lookup: ClassVar[dict[str, mpz]]

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        cls.base = mpz(len(cls.alphabet))
        cls.zero = cls.alphabet[0]
        cls.lookup = {c: mpz(i) for i, c in enumerate(cls.alphabet)}

    @classmethod
    def mpz_to_base(cls, number: mpz) -> str:
        result: list[str] = []
        while number:
            number, remainder = divmod(number, cls.base)
            result.append(cls.alphabet[int(remainder)])

        return "".join(reversed(result))

    @classmethod
    def base_to_mpz(cls, data: str) -> mpz:
        number = mpz(0)
        for digit in data:
            number = number * cls.base + cls.lookup[digit]

        return number

    @classmethod
    def encode(cls, data: bytes) -> str:
        if not data:
            return ""

        count = 0
        for i in data:
            if i == 0:
                count += 1
            else:
                break

        number = mpz.from_bytes(data, byteorder="big", signed=False)
        if number == 0:
            return cls.zero * count

        encoded = cls.mpz_to_base(number)
        return cls.zero * count + encoded

    @classmethod
    def decode(cls, data: str) -> bytes:
        stripped = data.lstrip(cls.zero)
        count = len(data) - len(stripped)
        if stripped:
            number = cls.base_to_mpz(stripped)
            byte_len = math.ceil(number.bit_length() / 8)
            decoded = number.to_bytes(byte_len, byteorder="big", signed=False)
        else:
            decoded = b""

        return b"\x00" * count + decoded
