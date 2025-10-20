from typing import cast

__all__ = ["base_to_bytes", "bytes_to_base", "decode_bytes", "encode_str"]


def encode_str(data: str) -> bytes:
    return data.encode(encoding="utf-8", errors="strict")


def decode_bytes(data: bytes) -> str:
    return data.decode(encoding="utf-8", errors="strict")


def int_to_base(number: int, alphabet: str) -> str:
    if number == 0:
        return alphabet[0]

    result: list[str] = []
    base = len(alphabet)
    abs_number = abs(number)
    while abs_number:
        abs_number, remainder = divmod(abs_number, base)
        result.append(alphabet[remainder])

    return "".join(reversed(result))


def base_to_int(source: str, alphabet: str) -> int:
    number = 0
    base = len(alphabet)
    for index, digit in enumerate(reversed(source)):
        number += alphabet.index(digit) * cast("int", base**index)

    return number


def bytes_to_base(source: bytes, alphabet: str) -> str:
    number = int.from_bytes(source, byteorder="big", signed=False)
    return int_to_base(number, alphabet)


def int_to_bytes(number: int) -> bytes:
    if number == 0:
        return b"\x00"

    buffer = bytearray()
    while number:
        buffer.append(number & 0xFF)
        number //= 256

    buffer.reverse()
    return bytes(buffer)


def base_to_bytes(source: str, alphabet: str) -> bytes:
    return int_to_bytes(base_to_int(source, alphabet))
