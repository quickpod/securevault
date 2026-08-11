#!/usr/bin/env python3
r"""
svtotp - RFC 6238 TOTP (and RFC 4226 HOTP) in pure standard library.

No third-party package and NO network - codes are computed locally from the
shared secret and the wall clock, so this respects SecureVault's "no inbound or
outbound connections" rule. Compatible with Google Authenticator, Authy, Aegis,
1Password, etc. (SHA-1, 6 digits, 30-second period).
"""
import os, hmac, hashlib, struct, base64, time


def random_secret(nbytes=20) -> str:
    """A fresh base32 shared secret (default 160-bit, the RFC 4226 recommendation)."""
    return base64.b32encode(os.urandom(nbytes)).decode("ascii").rstrip("=")


def _b32decode(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    s += "=" * (-len(s) % 8)                     # restore base32 padding
    return base64.b32decode(s, casefold=True)


# SHA-1 is the default because it is what essentially every issuer uses and what
# RFC 6238 assumes when otpauth:// omits the parameter. SHA-256 and SHA-512 are
# supported because some issuers DO specify them, and quietly computing SHA-1
# for those produces a plausible-looking six digits that is simply wrong - a
# failure that looks like a clock problem and wastes an hour.
_ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def _digestmod(algorithm: str):
    try:
        return _ALGORITHMS[(algorithm or "SHA1").upper()]
    except KeyError:
        raise ValueError(f"unsupported TOTP algorithm {algorithm!r}; "
                         f"expected one of {', '.join(_ALGORITHMS)}")


def hotp(secret: str, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    if counter < 0:                      # guard the epoch boundary in verify()
        counter = 0
    key = _b32decode(secret)
    mac = hmac.new(key, struct.pack(">Q", counter), _digestmod(algorithm)).digest()
    # Dynamic truncation, RFC 4226 5.3. The offset comes from the low nibble of
    # the LAST byte, so this is correct for every digest length, not just 20.
    off = mac[-1] & 0x0F
    val = struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF
    return str(val % (10 ** digits)).zfill(digits)


def totp(secret: str, at: float = None, step: int = 30, digits: int = 6,
         algorithm: str = "SHA1") -> str:
    if at is None:
        at = time.time()
    return hotp(secret, int(at // step), digits, algorithm)


def verify(secret: str, code: str, at: float = None, window: int = 1,
           step: int = 30, digits: int = 6, algorithm: str = "SHA1") -> bool:
    """True if `code` matches the current step or +/- `window` steps (clock skew)."""
    if not code or not code.isdigit():
        return False
    if at is None:
        at = time.time()
    for w in range(-window, window + 1):
        if hmac.compare_digest(totp(secret, at + w * step, step, digits, algorithm), code):
            return True
    return False


def provisioning_uri(secret: str, account: str, issuer: str = "SecureVault",
                     digits: int = 6, period: int = 30, algorithm: str = "SHA1") -> str:
    """otpauth:// URI you can paste/QR into an authenticator app."""
    def esc(s):
        return "".join(c if c.isalnum() or c in "-._~" else "%%%02X" % ord(c) for c in s)
    label = f"{esc(issuer)}:{esc(account)}"
    algorithm = (algorithm or "SHA1").upper()
    _digestmod(algorithm)                    # reject a bad algorithm at build time
    return (f"otpauth://totp/{label}?secret={secret}"
            f"&issuer={esc(issuer)}&algorithm={algorithm}&digits={digits}&period={period}")


if __name__ == "__main__":
    s = random_secret()
    print("secret:", s)
    print("uri   :", provisioning_uri(s, "you@example.com"))
    print("now   :", totp(s), " verifies:", verify(s, totp(s)))
