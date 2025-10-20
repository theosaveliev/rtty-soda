from nacl.encoding import RawEncoder
from nacl.hash import blake2b
from nacl.public import PrivateKey
from nacl.pwhash import argon2id
from nacl.pwhash.argon2id import (
    MEMLIMIT_INTERACTIVE,
    MEMLIMIT_MODERATE,
    MEMLIMIT_SENSITIVE,
    OPSLIMIT_INTERACTIVE,
    OPSLIMIT_MODERATE,
    OPSLIMIT_SENSITIVE,
    SALTBYTES,
)

__all__ = ["KDF_PROFILES", "KdfProfile", "hash_salt", "kdf"]

type KdfProfile = tuple[int, int]

KDF_PROFILES: dict[str, KdfProfile] = {
    "interactive": (OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE),
    "moderate": (OPSLIMIT_MODERATE, MEMLIMIT_MODERATE),
    "sensitive": (OPSLIMIT_SENSITIVE, MEMLIMIT_SENSITIVE),
}

SALT_MOD = b"""And here I solemnly protest I have no intention to vilify or asperse any
one; for though everything is copied from the book of nature, and scarce a character or
action produced which I have not taken from my own observations or experience; yet I
have used the utmost care to obscure the persons by such different circumstances,
degrees, and colors, that it will be impossible to guess at them with any degree of
certainty;
(c) Henry Fielding
"""


def hash_salt(salt: bytes) -> bytes:
    return blake2b(data=salt, digest_size=SALTBYTES, encoder=RawEncoder)


def kdf(password: bytes, profile: KdfProfile) -> bytes:
    salt = hash_salt(password + SALT_MOD)
    ops, mem = profile
    return argon2id.kdf(
        size=PrivateKey.SIZE,
        password=password,
        salt=salt,
        opslimit=ops,
        memlimit=mem,
        encoder=RawEncoder,
    )
