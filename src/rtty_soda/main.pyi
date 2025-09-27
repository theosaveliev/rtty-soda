from pathlib import Path

def cli() -> None: ...
def genkey_cmd(encoding: str) -> None: ...
def pubkey_cmd(private_key_file: Path, encoding: str) -> None: ...
def kdf_cmd(password_file: Path, encoding: str, profile: str) -> None: ...
def encrypt_public_cmd(
    private_key_file: Path,
    public_key_file: Path,
    message_file: Path,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None: ...
def encrypt_secret_cmd(
    key_file: Path,
    message_file: Path,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None: ...
def encrypt_password_cmd(
    password_file: Path,
    message_file: Path,
    kdf_profile: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None: ...
def decrypt_public_cmd(
    private_key_file: Path,
    public_key_file: Path,
    message_file: Path,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None: ...
def decrypt_secret_cmd(
    key_file: Path,
    message_file: Path,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None: ...
def decrypt_password_cmd(
    password_file: Path,
    message_file: Path,
    kdf_profile: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None: ...
def encode_cmd(
    in_encoding: str, out_encoding: str, file: Path, output_file: Path | None
) -> None: ...
