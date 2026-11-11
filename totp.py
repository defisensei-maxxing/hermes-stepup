"""RFC 6238 TOTP (SHA-1, 30 s, 6 digits). Standard library only."""
import base64
import hashlib
import hmac
import struct

STEP = 30
DIGITS = 6


def normalize_secret(secret):
    return "".join(str(secret or "").split()).replace("-", "").upper()


def code_at(secret_b32, counter):
    s = normalize_secret(secret_b32)
    key = base64.b32decode(s + "=" * (-len(s) % 8))
    mac = hmac.new(key, struct.pack(">Q", int(counter)), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    n = struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF
    return str(n % 10 ** DIGITS).zfill(DIGITS)


def verify(secret_b32, code, now, last_counter=-1, window=1):
    """Return the matched time-step counter, or None.

    A counter at or below last_counter is refused, so each code works once.
    """
    current = int(now) // STEP
    matched = None
    for counter in range(current - window, current + window + 1):
        ok = hmac.compare_digest(code_at(secret_b32, counter), str(code))
        if ok and counter > last_counter and matched is None:
            matched = counter
    return matched
