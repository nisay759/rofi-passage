"""TOTP codes computed in-process (TOT-1, RFC 6238), so no secret reaches argv."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

from .errors import RofiPassageError

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


@dataclass(frozen=True, repr=False)
class Totp:
    secret: bytes
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"

    def __repr__(self) -> str:  # keep the secret out of tracebacks and logs
        return f"Totp(digits={self.digits}, period={self.period}, algorithm={self.algorithm})"

    def code(self, now: float | None = None) -> str:
        counter = int((time.time() if now is None else now) // self.period)
        return hotp(self.secret, counter, self.digits, self.algorithm)

    def remaining(self, now: float | None = None) -> float:
        now = time.time() if now is None else now
        return self.period - (now % self.period)


def hotp(secret: bytes, counter: int, digits: int, algorithm: str) -> str:
    """RFC 4226 dynamic truncation."""
    mac = hmac.new(secret, struct.pack(">Q", counter), ALGORITHMS[algorithm]).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**digits).zfill(digits)


def _b32decode(secret: str) -> bytes:
    cleaned = secret.replace(" ", "").replace("-", "").upper()
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        return base64.b32decode(cleaned)
    except ValueError as e:
        raise RofiPassageError("Invalid TOTP secret (not base32)") from e


def parse(uri: str) -> Totp:
    """Parse an `otpauth://totp/` URI. Defaults: 6 digits, 30 s, SHA1."""
    parts = urlsplit(uri.strip())
    if parts.scheme != "otpauth":
        raise RofiPassageError("Not an otpauth:// URI")
    kind = parts.netloc.lower()
    if kind == "hotp":
        raise RofiPassageError("HOTP (counter-based) codes are not supported, only TOTP")
    if kind != "totp":
        raise RofiPassageError(f"Unsupported OTP type: {kind or 'missing'}")

    query = {k.lower(): v[-1] for k, v in parse_qs(parts.query).items()}
    secret = query.get("secret")
    if not secret:
        raise RofiPassageError("TOTP URI has no secret")
    try:
        digits = int(query.get("digits", "6"))
        period = int(query.get("period", "30"))
    except ValueError as e:
        raise RofiPassageError("TOTP digits and period must be numbers") from e
    algorithm = query.get("algorithm", "SHA1").upper().replace("-", "")
    if not 6 <= digits <= 8:
        raise RofiPassageError("TOTP digits must be 6 to 8")
    if period <= 0:
        raise RofiPassageError("TOTP period must be positive")
    if algorithm not in ALGORITHMS:
        raise RofiPassageError("TOTP algorithm must be SHA1, SHA256 or SHA512")
    return Totp(_b32decode(secret), digits, period, algorithm)


def fresh_code(totp: Totp, min_remaining: float = 5.0) -> str:
    """The current code, or the next one if fewer than `min_remaining` seconds are left."""
    left = totp.remaining()
    if left < min_remaining:
        time.sleep(left + 0.05)
    return totp.code()
