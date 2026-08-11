#!/usr/bin/env python3
r"""
make_ios_fixture - generate the cross-language test vectors for the iOS app.

WHY THIS EXISTS
The Swift .svb reader is written on a machine with no Mac and no Swift
compiler, so it cannot be run before it is pushed. The only honest way to
verify it is to have the Python side - which IS tested, by selftest_bundle -
emit a bundle plus the exact values a correct reader must recover, commit both,
and let the macOS CI runner prove the Swift decoder agrees.

If the Swift and Python implementations ever diverge, the CI test fails on a
concrete mismatch instead of the divergence being discovered on a phone with a
real seed phrase in it.

The TOTP entries deliberately use the RFC 6238 published test vectors, so the
Swift generator is checked against the specification rather than merely against
this Python module. Both being wrong the same way is the failure mode a
self-consistent fixture would not catch.

Output (written into the iOS repo):
    Tests/Fixtures/test-bundle.svb        the encrypted bundle
    Tests/Fixtures/expected.json          what a correct reader must produce

The passphrase and the secrets here are PUBLIC TEST VALUES from the RFC. They
guard nothing and are safe to commit. Nothing real goes in this file.
"""
import os, sys, json, base64

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import svbundle
import svtotp

PASSPHRASE = "correct horse battery staple"

# RFC 6238 Appendix B seeds and PUBLISHED codes.
#
# These constants are TRANSCRIBED FROM THE RFC, never computed by svtotp. That
# distinction caught a real bug: the first version of this file asked svtotp for
# a SHA-256 code, and svtotp had hashlib.sha1 hardcoded, so it returned a SHA-1
# code over the SHA-256 seed. The fixture was self-consistent and wrong, and the
# Swift - which was correct - failed against it. A generator that computes its
# own expectations can only ever prove the two sides agree, not that either is
# right.
SEED_SHA1 = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
SEED_SHA256 = base64.b32encode(b"12345678901234567890123456789012").decode().rstrip("=")
SEED_SHA512 = base64.b32encode(
    b"1234567890123456789012345678901234567890123456789012345678901234").decode().rstrip("=")

RFC_TIMES = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]

RFC_VECTORS = {
    "SHA1": (SEED_SHA1, ["94287082", "07081804", "14050471",
                         "89005924", "69279037", "65353130"]),
    "SHA256": (SEED_SHA256, ["46119246", "68084774", "67062674",
                             "91819424", "90698825", "77737706"]),
    "SHA512": (SEED_SHA512, ["90693936", "25091201", "99943326",
                             "93441116", "38618901", "47863826"]),
}

PHRASE = ("abandon abandon abandon abandon abandon abandon "
          "abandon abandon abandon abandon abandon about")

ITEMS = [
    {"type": "totp", "title": "RFC6238 SHA1", "issuer": "RFC", "account": "vectors",
     "secret": SEED_SHA1, "algorithm": "SHA1", "digits": 8, "period": 30},
    {"type": "totp", "title": "RFC6238 SHA256", "issuer": "RFC", "account": "vectors",
     "secret": SEED_SHA256, "algorithm": "SHA256", "digits": 8, "period": 30},
    {"type": "totp", "title": "Default 6-digit", "issuer": "Example", "account": "me@example.com",
     "secret": SEED_SHA1, "algorithm": "SHA1", "digits": 6, "period": 30, "tags": ["work"]},
    {"type": "seed", "title": "Test wallet", "phrase": PHRASE,
     "notes": "RFC-style all-zero BIP39 vector. Holds nothing.", "tags": ["seed"]},
]


def main():
    out_dir = (sys.argv[1] if len(sys.argv) > 1
               else r"S:\securevault-ios\Tests\SecureVaultCoreTests\Fixtures")
    os.makedirs(out_dir, exist_ok=True)

    # pbkdf2, because the CI test must pass with ZERO third-party Swift
    # dependencies. A scrypt fixture is generated too, so the scrypt path is
    # covered whenever a scrypt implementation is linked in.
    blob = svbundle.pack(ITEMS, PASSPHRASE, kdf="pbkdf2")
    with open(os.path.join(out_dir, "test-bundle.svb"), "wb") as f:
        f.write(blob)

    scrypt_blob = svbundle.pack(ITEMS, PASSPHRASE, kdf="scrypt")
    with open(os.path.join(out_dir, "test-bundle-scrypt.svb"), "wb") as f:
        f.write(scrypt_blob)

    # verify our own output before publishing it as a reference
    back = svbundle.unpack(blob, PASSPHRASE)
    assert len(back["items"]) == len(ITEMS), "fixture failed to round-trip"

    # Conformance check on the PYTHON side. This is not ceremony - it is the
    # check that failed to exist the first time round.
    rfc = {}
    for algorithm, (seed, codes) in sorted(RFC_VECTORS.items()):
        for at, want in zip(RFC_TIMES, codes):
            got = svtotp.totp(seed, at=at, digits=8, algorithm=algorithm)
            assert got == want, (
                f"svtotp disagrees with RFC 6238 {algorithm} at t={at}: {got} != {want}")
        rfc[algorithm.lower()] = {
            "secret": seed, "digits": 8, "algorithm": algorithm,
            "vectors": [{"time": t, "code": c} for t, c in zip(RFC_TIMES, codes)],
        }

    expected = {
        "passphrase": PASSPHRASE,
        "bundle": "test-bundle.svb",
        "bundleScrypt": "test-bundle-scrypt.svb",
        "wrongPassphrase": "not the passphrase",
        "itemCount": len(ITEMS),
        "items": back["items"],
        "rfc6238": rfc,
    }
    with open(os.path.join(out_dir, "expected.json"), "w", encoding="utf-8") as f:
        json.dump(expected, f, indent=2, sort_keys=True)

    print(f"wrote {out_dir}")
    print(f"  test-bundle.svb        {len(blob)} bytes (pbkdf2)")
    print(f"  test-bundle-scrypt.svb {len(scrypt_blob)} bytes (scrypt)")
    print(f"  expected.json          {len(ITEMS)} items")
    for algorithm in sorted(RFC_VECTORS):
        print(f"  RFC 6238 {algorithm:<6} {len(RFC_TIMES)} published vectors reproduced by svtotp")
    return 0


if __name__ == "__main__":
    sys.exit(main())
