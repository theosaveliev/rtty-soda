import pytest
from click.testing import CliRunner

from rtty_soda.cli import cli


@pytest.fixture
def password() -> str:
    """Return a password."""
    return "qwerty"


@pytest.fixture
def private_key() -> str:
    """Return the Private key derived from the password."""
    return "HqbvUXflAG+no3YS9njezZ3leyr8IwERAyeNoG2l41U="


@pytest.fixture
def private_key_b36() -> str:
    """Return the Private key in base36."""
    return "RI3SPTQ4MKW711QVZJYE9WIIG8HNBAE3ZFNQVM2QBN6S250ET"


@pytest.fixture
def public_key() -> str:
    """Return the Public key for the Private key."""
    return "oRwsrjBbIWddLRrpZ+HlX6eErIEzn9PiAj8TL6B4uh4="


@pytest.fixture
def encrypted_public() -> str:
    """Return the password encrypted with the Public module."""
    return "ZGDZTg5dUxd8GBxDXQlNuoVmjaJk5dPWboCgqnnZRbtBsFrFp11Wri69CbLFyA=="


@pytest.fixture
def encrypted_secret() -> str:
    """Return the password encrypted with the Secret module."""
    return "lRNA/8yQDMZv1MT45Pbt57/e7NHFupsbdjNkwqCY7GNIr+s9+fl6jSZapDcYug=="


@pytest.fixture
def encrypted_pw() -> str:
    """Return the password encrypted with the Password option."""
    return "ltZ0JPwwAVAlGOrrlGR/niKiMOQYmwryuBpPx+0EwCr7smb5sHTnte6S7EjPiw=="


def test_genkey() -> None:
    runner = CliRunner()
    encoders = ["base26", "base31", "base36", "base64", "base94", "binary"]
    args = [
        "genkey",
        "--group-len",
        "0",
        "--line-len",
        "0",
        "--padding",
        "0",
        "--encoding",
        "base64",
    ]
    for enc in encoders:
        args[-1] = enc
        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0
        assert len(result.stdout) > 25


def test_pubkey(private_key: str, public_key: str) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("private_key", "w", encoding="utf-8") as fd:
            fd.write(private_key)

        args = [
            "pubkey",
            "private_key",
            "--encoding",
            "base64",
            "--group-len",
            "0",
            "--line-len",
            "0",
            "--padding",
            "0",
        ]
        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0
        assert result.stdout.strip() == public_key


def test_kdf(password: str, private_key: str) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("password", "w", encoding="utf-8") as fd:
            fd.write(password)

        args = [
            "kdf",
            "password",
            "--encoding",
            "base64",
            "--profile",
            "interactive",
            "--group-len",
            "0",
            "--line-len",
            "0",
            "--padding",
            "0",
        ]
        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0
        assert result.stdout.strip() == private_key


def test_decrypt_public(
    private_key: str, public_key: str, encrypted_public: str, password: str
) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("private_key", "w", encoding="utf-8") as fd:
            fd.write(private_key)

        with open("public_key", "w", encoding="utf-8") as fd:
            fd.write(public_key)

        with open("message", "w", encoding="utf-8") as fd:
            fd.write(encrypted_public)

        args = [
            "decrypt-public",
            "private_key",
            "public_key",
            "message",
            "--key-encoding",
            "base64",
            "--data-encoding",
            "base64",
            "--compression",
            "raw",
        ]
        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0
        assert result.stdout.strip() == password


def test_decrypt_secret(private_key: str, encrypted_secret: str, password: str) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("secret_key", "w", encoding="utf-8") as fd:
            fd.write(private_key)

        with open("message", "w", encoding="utf-8") as fd:
            fd.write(encrypted_secret)

        args = [
            "decrypt-secret",
            "secret_key",
            "message",
            "--key-encoding",
            "base64",
            "--data-encoding",
            "base64",
            "--compression",
            "raw",
        ]
        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0
        assert result.stdout.strip() == password


def test_decrypt_password(password: str, encrypted_pw: str) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("password", "w", encoding="utf-8") as fd:
            fd.write(password)

        with open("message", "w", encoding="utf-8") as fd:
            fd.write(encrypted_pw)

        args = [
            "decrypt-password",
            "password",
            "message",
            "--kdf-profile",
            "interactive",
            "--data-encoding",
            "base64",
            "--compression",
            "raw",
        ]
        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0
        assert result.stdout.strip() == password


def test_encrypt_public(private_key: str, public_key: str, password: str) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("private_key", "w", encoding="utf-8") as fd:
            fd.write(private_key)

        with open("public_key", "w", encoding="utf-8") as fd:
            fd.write(public_key)

        with open("message", "w", encoding="utf-8") as fd:
            fd.write(password)

        args = [
            "encrypt-public",
            "private_key",
            "public_key",
            "message",
            "--key-encoding",
            "base64",
            "--data-encoding",
            "base64",
            "--compression",
            "raw",
            "--output-file",
            "encrypted",
            "--group-len",
            "0",
            "--line-len",
            "0",
            "--padding",
            "0",
        ]
        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0

        args = [
            "decrypt-public",
            "private_key",
            "public_key",
            "encrypted",
            "--key-encoding",
            "base64",
            "--data-encoding",
            "base64",
            "--compression",
            "raw",
        ]
        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0
        assert result.stdout.strip() == password


def test_encrypt_secret(private_key: str, password: str) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("secret_key", "w", encoding="utf-8") as fd:
            fd.write(private_key)

        with open("message", "w", encoding="utf-8") as fd:
            fd.write(password)

        args = [
            "encrypt-secret",
            "secret_key",
            "message",
            "--key-encoding",
            "base64",
            "--data-encoding",
            "base64",
            "--compression",
            "raw",
            "--output-file",
            "encrypted",
            "--group-len",
            "0",
            "--line-len",
            "0",
            "--padding",
            "0",
        ]
        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0

        args = [
            "decrypt-secret",
            "secret_key",
            "encrypted",
            "--key-encoding",
            "base64",
            "--data-encoding",
            "base64",
            "--compression",
            "raw",
        ]
        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0
        assert result.stdout.strip() == password


def test_encrypt_password(password: str) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("password", "w", encoding="utf-8") as fd:
            fd.write(password)

        args = [
            "encrypt-password",
            "password",
            "password",
            "--kdf-profile",
            "interactive",
            "--data-encoding",
            "base64",
            "--compression",
            "raw",
            "--output-file",
            "encrypted",
            "--group-len",
            "0",
            "--line-len",
            "0",
            "--padding",
            "0",
        ]
        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0

        args = [
            "decrypt-password",
            "password",
            "encrypted",
            "--kdf-profile",
            "interactive",
            "--data-encoding",
            "base64",
            "--compression",
            "raw",
        ]
        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0
        assert result.stdout.strip() == password


def test_encode_cmd(private_key: str, private_key_b36: str) -> None:
    runner = CliRunner()
    args = [
        "encode",
        "base64",
        "base36",
        "--group-len",
        "0",
        "--line-len",
        "0",
        "--padding",
        "0",
        "-",
    ]
    result = runner.invoke(cli, args=args, input=private_key)
    assert result.exit_code == 0
    assert result.stdout.strip() == private_key_b36
