"""Unit tests for stegtriage/patterns.py."""

from __future__ import annotations

import base64

import pytest

from stegtriage.patterns import (
    BASE64_PATTERN,
    FLAG_PATTERNS,
    HEX_PATTERN,
    extract_strings,
    scan_text,
    try_decode_base64,
    try_decode_hex,
)


# ---------------------------------------------------------------------------
# FLAG_PATTERNS
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "flag{simple}",
    "FLAG{uppercase}",
    "CTF{with_underscores}",
    "picoCTF{pico_flag}",
    "HTB{hackthebox}",
    "THM{tryhackme}",
])
def test_flag_patterns_match(text: str) -> None:
    assert any(p.search(text) for p in FLAG_PATTERNS), f"{text!r} should match a flag pattern"


@pytest.mark.parametrize("text", [
    "notaflag",
    "flag without braces",
    "{}",
    "a{b}",  # too short prefix
])
def test_flag_patterns_no_false_positive(text: str) -> None:
    assert not any(p.search(text) for p in FLAG_PATTERNS), f"{text!r} should not match"


# ---------------------------------------------------------------------------
# try_decode_base64
# ---------------------------------------------------------------------------

def test_base64_decode_printable() -> None:
    original = "Hello, stegtriage!"
    encoded = base64.b64encode(original.encode()).decode()
    result = try_decode_base64(encoded)
    assert result == original


def test_base64_decode_binary_magic() -> None:
    png_magic = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 10).decode()
    result = try_decode_base64(png_magic)
    assert result is not None
    assert "binary" in result


def test_base64_decode_non_base64_returns_none() -> None:
    assert try_decode_base64("not!!!valid===base64") is None


def test_base64_decode_non_printable_returns_none() -> None:
    raw = bytes(range(256))
    encoded = base64.b64encode(raw).decode()
    result = try_decode_base64(encoded)
    assert result is None


# ---------------------------------------------------------------------------
# try_decode_hex
# ---------------------------------------------------------------------------

def test_hex_decode_printable() -> None:
    original = "secret"
    encoded = original.encode().hex()
    result = try_decode_hex(encoded)
    assert result == original


def test_hex_decode_odd_length_returns_none() -> None:
    assert try_decode_hex("abc") is None  # odd length → invalid hex


def test_hex_decode_binary_magic() -> None:
    magic = (b"\x89PNG\r\n\x1a\n" + b"\x00" * 8).hex()
    result = try_decode_hex(magic)
    assert result is not None and "binary" in result


# ---------------------------------------------------------------------------
# scan_text
# ---------------------------------------------------------------------------

def test_scan_text_flag() -> None:
    hits = scan_text("prefix flag{found_it} suffix")
    flag_hits = [h for h in hits if h["pattern"] == "flag"]
    assert len(flag_hits) == 1
    assert flag_hits[0]["match"] == "flag{found_it}"


def test_scan_text_url() -> None:
    hits = scan_text("visit https://example.com/page for details")
    assert any(h["pattern"] == "url" for h in hits)


def test_scan_text_email() -> None:
    hits = scan_text("contact user@example.com for support")
    assert any(h["pattern"] == "email" for h in hits)


def test_scan_text_base64_with_encoded_flag() -> None:
    inner = "flag{base64_encoded_flag}"
    encoded = base64.b64encode(inner.encode()).decode()
    # Pad to ≥ 20 chars (it already is)
    hits = scan_text(encoded)
    b64_hit = next((h for h in hits if h["pattern"] == "base64"), None)
    assert b64_hit is not None
    assert b64_hit.get("decoded") is not None
    assert "flag" in b64_hit["decoded"]


def test_scan_text_no_hits_on_random_text() -> None:
    hits = scan_text("the quick brown fox jumps over the lazy dog")
    flag_hits = [h for h in hits if h["pattern"] == "flag"]
    assert flag_hits == []


# ---------------------------------------------------------------------------
# extract_strings
# ---------------------------------------------------------------------------

def test_extract_strings_basic() -> None:
    data = b"\x00\x00hello\x00world\x00\xff"
    result = extract_strings(data, min_len=5)
    assert "hello" in result
    assert "world" in result


def test_extract_strings_min_len_filters_short() -> None:
    data = b"\x00hi\x00hello\x00"
    assert "hi" not in extract_strings(data, min_len=5)
    assert "hello" in extract_strings(data, min_len=5)


def test_extract_strings_empty_data() -> None:
    assert extract_strings(b"\x00\xff\xfe\xfd", min_len=4) == []


def test_extract_strings_all_printable() -> None:
    data = b"abcdefghij"
    result = extract_strings(data, min_len=5)
    assert result == ["abcdefghij"]
