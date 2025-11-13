from pathlib import Path

from click import Command

cli: Command

def genkey_cmd(
    encoding: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None: ...
def pubkey_cmd(
    private_key_file: Path,
    encoding: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None: ...
def kdf_cmd(
    password_file: Path,
    encoding: str,
    profile: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None: ...
def encrypt_public_cmd(
    private_key_file: Path,
    public_key_file: Path,
    message_file: Path,
    text: bool,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None: ...
def encrypt_secret_cmd(
    key_file: Path,
    message_file: Path,
    text: bool,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None: ...
def encrypt_password_cmd(
    password_file: Path,
    message_file: Path,
    text: bool,
    kdf_profile: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None: ...
def decrypt_public_cmd(
    private_key_file: Path,
    public_key_file: Path,
    message_file: Path,
    text: bool,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None: ...
def decrypt_secret_cmd(
    key_file: Path,
    message_file: Path,
    text: bool,
    key_encoding: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None: ...
def decrypt_password_cmd(
    password_file: Path,
    message_file: Path,
    text: bool,
    kdf_profile: str,
    data_encoding: str,
    compression: str,
    output_file: Path | None,
) -> None: ...
def encode_cmd(
    in_encoding: str,
    out_encoding: str,
    file: Path,
    output_file: Path | None,
    group_len: int,
    line_len: int,
    padding: int,
    verbose: bool,
) -> None: ...
