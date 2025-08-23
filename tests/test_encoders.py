from rtty_soda.encoders import (
    Base26Encoder,
    Base36Encoder,
    Base64Encoder,
    Base94Encoder,
)


def test_encoders():
    assert Base26Encoder.encode(b"\x64") == b"DW"
    assert Base26Encoder.decode(b"DW") == b"\x64"

    assert Base36Encoder.encode(b"\x64") == b"2S"
    assert Base36Encoder.decode(b"2S") == b"\x64"

    assert Base64Encoder.encode(b"\x64") == b"ZA=="
    assert Base64Encoder.decode(b"ZA==") == b"\x64"

    assert Base94Encoder.encode(b"\x64") == b"\"'"
    assert Base94Encoder.decode(b"\"'") == b"\x64"
