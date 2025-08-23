# pylint: disable=redefined-outer-name
import pytest
from click.testing import CliRunner

from rtty_soda.main import cli


@pytest.fixture
def password():
    """Random password."""
    return "qwerty"


@pytest.fixture
def private_key():
    """The Private key derived from the password."""
    return "HqbvUXflAG+no3YS9njezZ3leyr8IwERAyeNoG2l41U="


@pytest.fixture
def private_key_b36():
    """The Private key in base36."""
    return "RI3SPTQ4MKW711QVZJYE9WIIG8HNBAE3ZFNQVM2QBN6S250ET"


@pytest.fixture
def public_key():
    """The Public key for the Private key."""
    return "oRwsrjBbIWddLRrpZ+HlX6eErIEzn9PiAj8TL6B4uh4="


@pytest.fixture
def encrypted_public():
    """The password encrypted with the Public module."""
    return "ZGDZTg5dUxd8GBxDXQlNuoVmjaJk5dPWboCgqnnZRbtBsFrFp11Wri69CbLFyA=="


@pytest.fixture
def encrypted_secret():
    """The password encrypted with the Secret module."""
    return "lRNA/8yQDMZv1MT45Pbt57/e7NHFupsbdjNkwqCY7GNIr+s9+fl6jSZapDcYug=="


@pytest.fixture
def encrypted_pw():
    """The password encrypted with the Password option."""
    return "ltZ0JPwwAVAlGOrrlGR/niKiMOQYmwryuBpPx+0EwCr7smb5sHTnte6S7EjPiw=="


def test_genkey():
    runner = CliRunner()
    text_encoders = ["base26", "base36", "base64", "base94"]
    for enc in text_encoders:
        result = runner.invoke(cli, ["genkey", "--encoding", enc])
        assert result.exit_code == 0
        assert len(result.stdout) > 30


def test_pubkey(private_key, public_key):
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("private_key", "w", encoding="utf-8") as fd:
            fd.write(private_key)

        args = ["pubkey", "private_key", "--encoding", "base64"]
        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0
        assert result.stdout.strip() == public_key


def test_kdf(password, private_key):
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
        ]
        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0
        assert result.stdout.strip() == private_key


def test_decrypt_public(private_key, public_key, encrypted_public, password):
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


def test_decrypt_secret(private_key, encrypted_secret, password):
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


def test_decrypt_password(password, encrypted_pw):
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


def test_encrypt_public(private_key, public_key, password):
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


def test_encrypt_secret(private_key, password):
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


def test_encrypt_password(password):
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


def test_encode_cmd(private_key, private_key_b36):
    runner = CliRunner()
    args = [
        "encode",
        "base64",
        "base36",
        "-",
    ]
    result = runner.invoke(cli, args=args, input=private_key)
    assert result.exit_code == 0
    assert result.stdout.strip() == private_key_b36
