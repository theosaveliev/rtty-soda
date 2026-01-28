from rtty_soda.encoders import (
    Base10Encoder,
    Base26Encoder,
    Base31Encoder,
    Base32Encoder,
    Base36Encoder,
    Base64Encoder,
    Base94Encoder,
)


def test_encoders() -> None:
    assert Base10Encoder.encode(b"\x64") == "100"
    assert Base10Encoder.decode("100") == b"\x64"

    assert Base26Encoder.encode(b"\x64") == "DW"
    assert Base26Encoder.decode("DW") == b"\x64"

    assert Base31Encoder.encode(b"\x64") == "ГЗ"
    assert Base31Encoder.decode("ГЗ") == b"\x64"

    assert Base32Encoder.encode(b"\x64") == "MQ======"
    assert Base32Encoder.decode("MQ======") == b"\x64"

    assert Base36Encoder.encode(b"\x64") == "2S"
    assert Base36Encoder.decode("2S") == b"\x64"

    assert Base64Encoder.encode(b"\x64") == "ZA=="
    assert Base64Encoder.decode("ZA==") == b"\x64"

    assert Base94Encoder.encode(b"\x64") == "\"'"
    assert Base94Encoder.decode("\"'") == b"\x64"
