from rtty_soda.encoders import (
    Base26Encoder,
    Base31Encoder,
    Base36Encoder,
    Base64Encoder,
    Base94Encoder,
    RawEncoder,
)


def test_encoders() -> None:
    assert Base26Encoder.encode(b"\x64") == b"DW"
    assert Base26Encoder.decode(b"DW") == b"\x64"

    one_hundred_b31 = "ГЗ".encode(encoding="utf-8", errors="strict")
    assert Base31Encoder.encode(b"\x64") == one_hundred_b31
    assert Base31Encoder.decode(one_hundred_b31) == b"\x64"

    assert Base36Encoder.encode(b"\x64") == b"2S"
    assert Base36Encoder.decode(b"2S") == b"\x64"

    assert Base64Encoder.encode(b"\x64") == b"ZA=="
    assert Base64Encoder.decode(b"ZA==") == b"\x64"

    assert Base94Encoder.encode(b"\x64") == b"\"'"
    assert Base94Encoder.decode(b"\"'") == b"\x64"

    assert RawEncoder.encode(b"\x64") == b"\x64"
    assert RawEncoder.decode(b"\x64") == b"\x64"
