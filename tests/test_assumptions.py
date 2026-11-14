from nacl.public import Box, PrivateKey
from nacl.secret import SecretBox

from rtty_soda.cryptography.short_nonce import FULL_NONCE_LEN


def test_assumptions() -> None:
    # I'd like to use the PrivateKey.__bytes__() as the Secret Key.
    # That's Ok as long as the lengths match:
    assert PrivateKey.SIZE == SecretBox.KEY_SIZE

    # Check default nonce size for the --short-nonce flow
    assert Box.NONCE_SIZE == SecretBox.NONCE_SIZE == FULL_NONCE_LEN
