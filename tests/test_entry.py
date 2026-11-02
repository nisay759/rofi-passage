from rofi_passage.entry import Entry, public_fields

SAMPLE = (
    b"S3cret-password\n"
    b"username: alice@example.com\n"
    b"url: https://www.example.com\n"
    b"security question: blue\n"
    b"recovery: 1234 5678\n"
    b"recovery: 2345 6789\n"
    b"otpauth://totp/example.com:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=example.com\n"
)


def test_contract_sample() -> None:
    e = Entry(SAMPLE)
    assert e.password == "S3cret-password"
    assert e.username == "alice@example.com"
    assert e.url == "https://www.example.com"
    assert e.get("security question") == "blue"
    assert [f.value for f in e.recovery] == ["1234 5678", "2345 6789"]
    assert e.otpauth is not None and e.otpauth.startswith("otpauth://totp/example.com:")


def test_key_value_rules() -> None:
    e = Entry(b"pw\nkey   :  two spaces\nempty:\nnospace:x\n: no key\n")
    assert e.get("key") == " two spaces"  # trailing spaces of key trimmed, one leading removed
    assert e.get("empty") == ""
    assert e.get("nospace") == "x"
    assert [f.key for f in e.fields] == ["key", "empty", "nospace"]


def test_login_fallback_and_username_priority() -> None:
    assert Entry(b"pw\nlogin: bob\n").username == "bob"
    assert Entry(b"pw\nlogin: bob\nusername: alice\n").username == "alice"
    assert Entry(b"pw\n").username is None


def test_line_one_is_never_a_field() -> None:
    e = Entry(b"user: not-a-field\nusername: a\n")
    assert e.password == "user: not-a-field"
    assert e.get("user") is None


def test_totp_only_entry() -> None:
    uri = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"
    e = Entry(uri.encode() + b"\n")
    assert e.password == uri
    assert e.otpauth == uri
    assert e.fields == []


def test_first_otpauth_wins() -> None:
    e = Entry(b"pw\notpauth://totp/a?secret=AAAA\notpauth://totp/b?secret=BBBB\n")
    assert e.otpauth == "otpauth://totp/a?secret=AAAA"


def test_without_line_is_byte_faithful() -> None:
    raw = b"pw\nfree text \xff\xfe kept\nrecovery: 1\r\nrecovery: 2\nno final newline"
    e = Entry(raw)
    r2 = e.recovery[1]
    assert e.without_line(r2.line) == raw.replace(b"recovery: 2\n", b"")
    r1 = e.recovery[0]
    assert r1.value == "1"  # CR stripped from the parsed value only
    assert e.without_line(r1.line) == raw.replace(b"recovery: 1\r\n", b"")


def test_lone_cr_does_not_split_lines() -> None:
    e = Entry(b"pw\nnote: a\rb\n")
    assert len(e.lines) == 2
    assert e.get("note") == "a\rb"


def test_public_fields_hide_secrets() -> None:
    keys = [f.key for f in public_fields(Entry(SAMPLE))]
    assert keys == ["username", "url", "security question"]


def test_empty_entry() -> None:
    e = Entry(b"")
    assert e.password == ""
    assert e.lines == []
