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
def private_key_b32() -> str:
    """Return the Private key in base32."""
    return "D2TO6ULX4UAG7J5DOYJPM6G6ZWO6K6ZK7QRQCEIDE6G2A3NF4NKQ===="


@pytest.fixture
def private_key_b36() -> str:
    """Return the Private key in base36."""
    return "RI3SPTQ4MKW711QVZJYE9WIIG8HNBAE3ZFNQVM2QBN6S250ET"


@pytest.fixture
def private_key_protected() -> str:
    """Return the Private key protected with passphrase."""
    return (
        "bD+krNPhHdeZ4X6g6nNS07CRRdQzDTxv5XGv3okabpYraq2/BqGJ/mp3zVtFDfg4K3OGmrvd"
        "aH5sBqiGI1wN0l+VY5N6hIUe"
    )


@pytest.fixture
def passphrase() -> str:
    """Return the passphrase."""
    return "test passphrase"


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


def test_genkey() -> None:
    runner = CliRunner()
    encoders = [
        "base10",
        "base26",
        "base31",
        "base32",
        "base36",
        "base64",
        "base94",
        "binary",
    ]

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


@pytest.mark.slow
def test_genkey_passphrase(passphrase: str) -> None:
    runner = CliRunner()

    args = [
        "genkey",
        "--key-passphrase",
        passphrase,
        "--group-len",
        "0",
        "--line-len",
        "0",
        "--padding",
        "0",
        "--encoding",
        "base64",
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0
    assert len(result.stdout) > 90


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


@pytest.mark.slow
def test_pubkey_passphrase(
    private_key_protected: str, passphrase: str, public_key: str
) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("private_key_protected", "w", encoding="utf-8") as fd:
            fd.write(private_key_protected)

        args = [
            "pubkey",
            "private_key_protected",
            "--key-passphrase",
            passphrase,
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


def test_decrypt_public(
    private_key: str, public_key: str, encrypted_public: str, password: str
) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("private_key", "w", encoding="utf-8") as fd:
            fd.write(private_key)

        with open("public_key", "w", encoding="utf-8") as fd:
            fd.write(public_key)

        with open("encrypted_public", "w", encoding="utf-8") as fd:
            fd.write(encrypted_public)

        args = [
            "decrypt-public",
            "private_key",
            "public_key",
            "encrypted_public",
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


@pytest.mark.slow
def test_decrypt_public_passphrase(
    private_key_protected: str,
    passphrase: str,
    public_key: str,
    encrypted_public: str,
    password: str,
) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("private_key_protected", "w", encoding="utf-8") as fd:
            fd.write(private_key_protected)

        with open("public_key", "w", encoding="utf-8") as fd:
            fd.write(public_key)

        with open("encrypted_public", "w", encoding="utf-8") as fd:
            fd.write(encrypted_public)

        args = [
            "decrypt-public",
            "private_key_protected",
            "public_key",
            "encrypted_public",
            "--key-passphrase",
            passphrase,
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
        with open("private_key", "w", encoding="utf-8") as fd:
            fd.write(private_key)

        with open("encrypted_secret", "w", encoding="utf-8") as fd:
            fd.write(encrypted_secret)

        args = [
            "decrypt-secret",
            "private_key",
            "encrypted_secret",
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


@pytest.mark.slow
def test_decrypt_secret_passphrase(
    private_key_protected: str, passphrase: str, encrypted_secret: str, password: str
) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("private_key_protected", "w", encoding="utf-8") as fd:
            fd.write(private_key_protected)

        with open("encrypted_secret", "w", encoding="utf-8") as fd:
            fd.write(encrypted_secret)

        args = [
            "decrypt-secret",
            "private_key_protected",
            "encrypted_secret",
            "--key-passphrase",
            passphrase,
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


def test_decrypt_password(password: str, encrypted_secret: str) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("password", "w", encoding="utf-8") as fd:
            fd.write(password)

        with open("encrypted_secret", "w", encoding="utf-8") as fd:
            fd.write(encrypted_secret)

        args = [
            "decrypt-password",
            "password",
            "encrypted_secret",
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

        with open("password", "w", encoding="utf-8") as fd:
            fd.write(password)

        args = [
            "encrypt-public",
            "private_key",
            "public_key",
            "password",
            "--key-encoding",
            "base64",
            "--data-encoding",
            "base64",
            "--compression",
            "raw",
            "--output-file",
            "encrypted_password",
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
            "encrypted_password",
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


@pytest.mark.slow
def test_encrypt_public_passphrase(
    private_key_protected: str, passphrase: str, public_key: str, password: str
) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("private_key_protected", "w", encoding="utf-8") as fd:
            fd.write(private_key_protected)

        with open("public_key", "w", encoding="utf-8") as fd:
            fd.write(public_key)

        with open("password", "w", encoding="utf-8") as fd:
            fd.write(password)

        args = [
            "encrypt-public",
            "private_key_protected",
            "public_key",
            "password",
            "--key-passphrase",
            passphrase,
            "--key-encoding",
            "base64",
            "--data-encoding",
            "base64",
            "--compression",
            "raw",
            "--output-file",
            "encrypted_password",
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
            "private_key_protected",
            "public_key",
            "encrypted_password",
            "--key-passphrase",
            passphrase,
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
        with open("private_key", "w", encoding="utf-8") as fd:
            fd.write(private_key)

        with open("password", "w", encoding="utf-8") as fd:
            fd.write(password)

        args = [
            "encrypt-secret",
            "private_key",
            "password",
            "--key-encoding",
            "base64",
            "--data-encoding",
            "base64",
            "--compression",
            "raw",
            "--output-file",
            "encrypted_password",
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
            "private_key",
            "encrypted_password",
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


@pytest.mark.slow
def test_encrypt_secret_passphrase(
    private_key_protected: str, passphrase: str, password: str
) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("private_key_protected", "w", encoding="utf-8") as fd:
            fd.write(private_key_protected)

        with open("password", "w", encoding="utf-8") as fd:
            fd.write(password)

        args = [
            "encrypt-secret",
            "private_key_protected",
            "password",
            "--key-passphrase",
            passphrase,
            "--key-encoding",
            "base64",
            "--data-encoding",
            "base64",
            "--compression",
            "raw",
            "--output-file",
            "encrypted_password",
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
            "private_key_protected",
            "encrypted_password",
            "--key-passphrase",
            passphrase,
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
            "encrypted_password",
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
            "encrypted_password",
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


@pytest.mark.slow
def test_kdf_passphrase(password: str, passphrase: str, private_key: str) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("password", "w", encoding="utf-8") as fd:
            fd.write(password)

        args = [
            "kdf",
            "password",
            "--key-passphrase",
            passphrase,
            "--encoding",
            "base64",
            "--profile",
            "interactive",
            "--output-file",
            "protected_key",
            "--group-len",
            "0",
            "--line-len",
            "0",
            "--padding",
            "0",
        ]

        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0

        with open("passphrase", "w", encoding="utf-8") as fd:
            fd.write(passphrase)

        args = [
            "decrypt-password",
            "passphrase",
            "protected_key",
            "--kdf-profile",
            "sensitive",
            "--data-encoding",
            "base64",
            "--compression",
            "raw",
            "--output-file",
            "unprotected_key",
        ]

        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0

        args = [
            "encode",
            "binary",
            "base64",
            "unprotected_key",
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


def test_google_auth(private_key_b32: str) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("key", "w", encoding="utf-8") as fd:
            fd.write(private_key_b32)

        args = ["google-auth", "key"]
        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0
        assert len(result.stdout) > 22


def test_help_screens() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, args="encodings")
    assert result.exit_code == 0
    assert len(result.stdout) > 180

    result = runner.invoke(cli, args="compression")
    assert result.exit_code == 0
    assert len(result.stdout) > 50

    result = runner.invoke(cli, args="kdf-profiles")
    assert result.exit_code == 0
    assert len(result.stdout) > 60
