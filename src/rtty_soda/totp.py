import hashlib
import time
from typing import TYPE_CHECKING

from pyotp import TOTP

if TYPE_CHECKING:
    from rtty_soda.interfaces import Reader

__all__ = ["GoogleAuthenticator"]


class GoogleAuthenticator:
    def __init__(self, key: Reader) -> None:
        self.secret = key.read_str().strip()
        self.totp = TOTP(s=self.secret, digits=6, digest=hashlib.sha1, interval=30)

    def get_code(self) -> str:
        code = self.totp.now()
        return f"{code[:3]} {code[3:]}"

    def get_remaining_seconds(self) -> int:
        interval = self.totp.interval
        return interval - int(time.time()) % interval
