from nacl.public import PrivateKey
from nacl.secret import SecretBox


def test_assumptions():
    # I'd like to use the PrivateKey.__bytes__() as the Secret Key.
    # That's Ok as long as the lengths match:
    assert PrivateKey.SIZE == SecretBox.KEY_SIZE
