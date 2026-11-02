import pytest

from rofi_passage import totp
from rofi_passage.errors import RofiPassageError

# RFC 6238 appendix B: ASCII seeds of 20, 32 and 64 bytes, 8 digits.
SEEDS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",
}
VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


@pytest.mark.parametrize(("t", "sha1", "sha256", "sha512"), VECTORS)
def test_rfc6238_vectors(t: int, sha1: str, sha256: str, sha512: str) -> None:
    for alg, expected in (("SHA1", sha1), ("SHA256", sha256), ("SHA512", sha512)):
        assert totp.Totp(SEEDS[alg], 8, 30, alg).code(t) == expected


def test_parse_defaults() -> None:
    t = totp.parse("otpauth://totp/example.com:alice?secret=JBSWY3DPEHPK3PXP&issuer=example.com")
    assert (t.digits, t.period, t.algorithm) == (6, 30, "SHA1")
    assert t.secret == b"Hello!\xde\xad\xbe\xef"


def test_parse_options_and_lowercase_padding() -> None:
    t = totp.parse("otpauth://totp/x?secret=jbsw y3dp&digits=8&period=60&algorithm=sha256")
    assert (t.digits, t.period, t.algorithm) == (8, 60, "SHA256")
    assert len(t.code(0)) == 8


@pytest.mark.parametrize(
    ("uri", "message"),
    [
        ("otpauth://hotp/x?secret=JBSWY3DP&counter=1", "HOTP"),
        ("otpauth://totp/x", "no secret"),
        ("otpauth://totp/x?secret=JBSWY3DP&digits=9", "6 to 8"),
        ("otpauth://totp/x?secret=JBSWY3DP&algorithm=MD5", "algorithm"),
        ("otpauth://totp/x?secret=!!!", "base32"),
        ("https://example.com", "otpauth"),
    ],
)
def test_parse_errors(uri: str, message: str) -> None:
    with pytest.raises(RofiPassageError, match=message):
        totp.parse(uri)


def test_repr_hides_secret() -> None:
    assert "secret" not in repr(totp.parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"))


def test_remaining() -> None:
    t = totp.Totp(b"x")
    assert t.remaining(60) == 30
    assert t.remaining(89) == 1
