from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from rtty_soda.cli import cli

if TYPE_CHECKING:
    from pathlib import Path

FMT = ("--group-len", "0", "--line-len", "0", "--padding", "0")
ENC = ("--key-encoding", "base64", "--data-encoding", "base64", "--compression", "raw")


def test_genkey() -> None:
    runner = CliRunner()
    args = ["genkey", *FMT, "--encoding", "base64"]

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

    for enc in encoders:
        args[-1] = enc
        result = runner.invoke(cli, args=args)
        assert result.exit_code == 0, result.output
        assert len(result.stdout) > 25


@pytest.mark.slow
def test_genkey_passphrase(passphrase: str) -> None:
    runner = CliRunner()
    args = ["genkey", "--key-passphrase", passphrase, *FMT, "--encoding", "base64"]
    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    assert len(result.stdout) > 90


def test_pubkey(private_key_file: Path, public_key: str) -> None:
    runner = CliRunner()
    args = ["pubkey", str(private_key_file), "--encoding", "base64", *FMT]
    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == public_key


@pytest.mark.slow
def test_pubkey_passphrase(
    pk_protected_file: Path, passphrase: str, public_key: str
) -> None:
    runner = CliRunner()

    args = [
        "pubkey",
        str(pk_protected_file),
        "--key-passphrase",
        passphrase,
        *FMT,
        "--encoding",
        "base64",
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == public_key


def test_decrypt_public(
    private_key_file: Path,
    public_key_file: Path,
    encrypted_public_file: Path,
    password: str,
) -> None:
    runner = CliRunner()

    args = [
        "decrypt-public",
        str(private_key_file),
        str(public_key_file),
        str(encrypted_public_file),
        *ENC,
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == password


@pytest.mark.slow
def test_decrypt_public_passphrase(
    pk_protected_file: Path,
    passphrase: str,
    public_key_file: Path,
    encrypted_public_file: Path,
    password: str,
) -> None:
    runner = CliRunner()

    args = [
        "decrypt-public",
        str(pk_protected_file),
        str(public_key_file),
        str(encrypted_public_file),
        "--key-passphrase",
        passphrase,
        *ENC,
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == password


def test_decrypt_secret(
    private_key_file: Path, encrypted_secret_file: Path, password: str
) -> None:
    runner = CliRunner()
    args = ["decrypt-secret", str(private_key_file), str(encrypted_secret_file), *ENC]
    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == password


@pytest.mark.slow
def test_decrypt_secret_passphrase(
    pk_protected_file: Path, passphrase: str, encrypted_secret_file: Path, password: str
) -> None:
    runner = CliRunner()

    args = [
        "decrypt-secret",
        str(pk_protected_file),
        str(encrypted_secret_file),
        "--key-passphrase",
        passphrase,
        *ENC,
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == password


@pytest.mark.slow
def test_decrypt_password(
    password: str, password_file: Path, encrypted_secret_file: Path
) -> None:
    runner = CliRunner()

    args = [
        "decrypt-password",
        str(password_file),
        str(encrypted_secret_file),
        "--kdf-profile",
        "interactive",
        "--data-encoding",
        "base64",
        "--compression",
        "raw",
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == password


def test_encrypt_public(
    password: str,
    password_file: Path,
    private_key_file: Path,
    public_key_file: Path,
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    encrypted = tmp_path / "encrypted_password"

    args = [
        "encrypt-public",
        str(private_key_file),
        str(public_key_file),
        str(password_file),
        *FMT,
        *ENC,
        "--output-file",
        str(encrypted),
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output

    args = [
        "decrypt-public",
        str(private_key_file),
        str(public_key_file),
        str(encrypted),
        *ENC,
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == password


@pytest.mark.slow
def test_encrypt_public_passphrase(
    password: str,
    password_file: Path,
    passphrase: str,
    pk_protected_file: Path,
    public_key_file: Path,
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    encrypted = tmp_path / "encrypted_password"

    args = [
        "encrypt-public",
        str(pk_protected_file),
        str(public_key_file),
        str(password_file),
        "--key-passphrase",
        passphrase,
        *FMT,
        *ENC,
        "--output-file",
        str(encrypted),
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output

    args = [
        "decrypt-public",
        str(pk_protected_file),
        str(public_key_file),
        str(encrypted),
        "--key-passphrase",
        passphrase,
        *ENC,
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == password


def test_encrypt_secret(
    password: str, password_file: Path, private_key_file: Path, tmp_path: Path
) -> None:
    runner = CliRunner()
    encrypted = tmp_path / "encrypted_password"

    args = [
        "encrypt-secret",
        str(private_key_file),
        str(password_file),
        *FMT,
        *ENC,
        "--output-file",
        str(encrypted),
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    args = ["decrypt-secret", str(private_key_file), str(encrypted), *ENC]
    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == password


@pytest.mark.slow
def test_encrypt_secret_passphrase(
    password: str,
    password_file: Path,
    pk_protected_file: Path,
    passphrase: str,
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    encrypted = tmp_path / "encrypted_password"

    args = [
        "encrypt-secret",
        str(pk_protected_file),
        str(password_file),
        "--key-passphrase",
        passphrase,
        *FMT,
        *ENC,
        "--output-file",
        str(encrypted),
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output

    args = [
        "decrypt-secret",
        str(pk_protected_file),
        str(encrypted),
        "--key-passphrase",
        passphrase,
        *ENC,
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == password


@pytest.mark.slow
def test_encrypt_password(password: str, password_file: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    encrypted = tmp_path / "encrypted_password"

    args = [
        "encrypt-password",
        str(password_file),
        str(password_file),
        "--kdf-profile",
        "interactive",
        "--data-encoding",
        "base64",
        "--compression",
        "raw",
        *FMT,
        "--output-file",
        str(encrypted),
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output

    args = [
        "decrypt-password",
        str(password_file),
        str(encrypted),
        "--kdf-profile",
        "interactive",
        "--data-encoding",
        "base64",
        "--compression",
        "raw",
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == password


def test_encode_cmd(private_key: str, private_key_b36: str) -> None:
    runner = CliRunner()
    args = ["encode", "base64", "base36", *FMT, "-"]
    result = runner.invoke(cli, args=args, input=private_key)
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == private_key_b36


@pytest.mark.slow
def test_kdf(password_file: Path, private_key: str) -> None:
    runner = CliRunner()

    args = [
        "kdf",
        str(password_file),
        "--encoding",
        "base64",
        "--profile",
        "interactive",
        *FMT,
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == private_key


@pytest.mark.slow
def test_kdf_passphrase(
    password_file: Path,
    passphrase: str,
    passphrase_file: Path,
    private_key: str,
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    derived = tmp_path / "derived"
    pkey = tmp_path / "private_key"

    args = [
        "kdf",
        str(password_file),
        "--key-passphrase",
        passphrase,
        "--encoding",
        "base64",
        "--profile",
        "interactive",
        *FMT,
        "--output-file",
        str(derived),
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output

    args = [
        "decrypt-password",
        str(passphrase_file),
        str(derived),
        "--kdf-profile",
        "sensitive",
        "--data-encoding",
        "base64",
        "--compression",
        "raw",
        "--output-file",
        str(pkey),
    ]

    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    args = ["encode", "binary", "base64", str(pkey), *FMT]
    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == private_key


def test_google_auth(private_key_b32_file: Path) -> None:
    runner = CliRunner()
    args = ["google-auth", str(private_key_b32_file)]
    result = runner.invoke(cli, args=args)
    assert result.exit_code == 0, result.output
    assert len(result.stdout) > 22


def test_help_screens() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, args="encodings")
    assert result.exit_code == 0, result.output
    assert len(result.stdout) > 180
    result = runner.invoke(cli, args="compression")
    assert result.exit_code == 0, result.output
    assert len(result.stdout) > 50
    result = runner.invoke(cli, args="kdf-profiles")
    assert result.exit_code == 0, result.output
    assert len(result.stdout) > 60
