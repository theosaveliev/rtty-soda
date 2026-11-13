from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


def write(directory: Path, name: str, content: str) -> Path:
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def password() -> str:
    """Return the password."""
    return "qwerty"


@pytest.fixture
def password_file(password: str, tmp_path: Path) -> Path:
    """Return the path to the password file."""
    return write(tmp_path, "password", password)


@pytest.fixture
def private_key() -> str:
    """Return the private key derived from the password."""
    return "HqbvUXflAG+no3YS9njezZ3leyr8IwERAyeNoG2l41U="


@pytest.fixture
def private_key_file(private_key: str, tmp_path: Path) -> Path:
    """Return the path to the private key file."""
    return write(tmp_path, "private_key", private_key)


@pytest.fixture
def private_key_b32_file(tmp_path: Path) -> Path:
    """Return the path to the base32 private key file."""
    key = "D2TO6ULX4UAG7J5DOYJPM6G6ZWO6K6ZK7QRQCEIDE6G2A3NF4NKQ===="
    return write(tmp_path, "private_key_b32", key)


@pytest.fixture
def private_key_b36() -> str:
    """Return the private key in base36."""
    return "RI3SPTQ4MKW711QVZJYE9WIIG8HNBAE3ZFNQVM2QBN6S250ET"


@pytest.fixture
def pk_protected_file(tmp_path: Path) -> Path:
    """Return the path to the passphrase-protected private key file."""
    key = (
        "bD+krNPhHdeZ4X6g6nNS07CRRdQzDTxv5XGv3okabpYraq2/BqGJ/mp3zVtFDfg4K3OGmrvdaH"
        "5sBqiGI1wN0l+VY5N6hIUe"
    )
    return write(tmp_path, "private_key_protected", key)


@pytest.fixture
def passphrase() -> str:
    """Return the passphrase."""
    return "test passphrase"


@pytest.fixture
def passphrase_file(passphrase: str, tmp_path: Path) -> Path:
    """Return the path to the passphrase file."""
    return write(tmp_path, "passphrase", passphrase)


@pytest.fixture
def public_key() -> str:
    """Return the public key for the private key."""
    return "oRwsrjBbIWddLRrpZ+HlX6eErIEzn9PiAj8TL6B4uh4="


@pytest.fixture
def public_key_file(public_key: str, tmp_path: Path) -> Path:
    """Return the path to the public key file."""
    return write(tmp_path, "public_key", public_key)


@pytest.fixture
def encrypted_public_file(tmp_path: Path) -> Path:
    """Return the path to the public-encrypted password file."""
    txt = "ZGDZTg5dUxd8GBxDXQlNuoVmjaJk5dPWboCgqnnZRbtBsFrFp11Wri69CbLFyA=="
    return write(tmp_path, "encrypted_public", txt)


@pytest.fixture
def encrypted_secret_file(tmp_path: Path) -> Path:
    """Return the path to the secret-encrypted password file."""
    txt = "lRNA/8yQDMZv1MT45Pbt57/e7NHFupsbdjNkwqCY7GNIr+s9+fl6jSZapDcYug=="
    return write(tmp_path, "encrypted_secret", txt)
