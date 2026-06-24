from __future__ import annotations

import base64
import re

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

FLAG_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
    re.compile(r'CTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'picoCTF\{[^}]+\}', re.IGNORECASE),
    # Generic WORD{...} for other CTF brands (e.g. HTB{}, THM{})
    re.compile(r'[A-Z]{2,10}\{[^}]{1,100}\}'),
]

URL_PATTERN = re.compile(
    r'https?://[^\s<>"{}|\\^`\[\]]+',
    re.IGNORECASE,
)

ONION_PATTERN = re.compile(r'[a-z2-7]{16,56}\.onion', re.IGNORECASE)

EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

# ≥ 20 chars of valid base64, properly padded or unpadded
BASE64_PATTERN = re.compile(
    r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})'
)

# Even-length run of hex chars, at least 16 hex chars (8 bytes)
HEX_PATTERN = re.compile(r'\b(?:[0-9a-fA-F]{2}){8,}\b')

PEM_PATTERN = re.compile(r'-----BEGIN [A-Z ]+-----')

PRIVKEY_PATTERN = re.compile(
    r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
)

# Binary magic bytes that signal embedded archives/files (used on raw bytes)
MAGIC_BYTES_PATTERN = re.compile(
    rb'PK\x03\x04|Rar!\x1a|7z\xbc\xaf\x27\x1c|\x1f\x8b\x08'
)


# ---------------------------------------------------------------------------
# Decode helpers
# ---------------------------------------------------------------------------

def _printable_ratio(data: bytes) -> float:
    printable = sum(1 for b in data if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    return printable / max(len(data), 1)


_KNOWN_MAGIC = (b'PK', b'\x1f\x8b', b'%PDF', b'\x89PNG', b'\xff\xd8\xff', b'GIF8')


def try_decode_base64(s: str) -> str | None:
    """Decode a base64 string; return decoded text if printable, a magic tag if binary, else None."""
    try:
        padded = s + '=' * (-len(s) % 4)
        decoded = base64.b64decode(padded)
        for magic in _KNOWN_MAGIC:
            if decoded.startswith(magic):
                return f"[binary: magic={decoded[:4].hex()}]"
        if _printable_ratio(decoded) > 0.80:
            return decoded.decode('utf-8', errors='replace')
    except Exception:
        pass
    return None


def try_decode_hex(s: str) -> str | None:
    """Decode a hex string; return decoded text if printable, a magic tag if binary, else None."""
    try:
        decoded = bytes.fromhex(s)
        for magic in _KNOWN_MAGIC:
            if decoded.startswith(magic):
                return f"[binary: magic={decoded[:4].hex()}]"
        if _printable_ratio(decoded) > 0.80:
            return decoded.decode('utf-8', errors='replace')
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Text scanner
# ---------------------------------------------------------------------------

def scan_text(text: str) -> list[dict]:
    """Scan *text* for high-value forensic patterns.

    Returns a list of hit dicts with at minimum keys ``pattern`` and ``match``.
    Base64/hex hits include a ``decoded`` key (may be None).
    """
    hits: list[dict] = []

    for pat in FLAG_PATTERNS:
        for m in pat.finditer(text):
            hits.append({"pattern": "flag", "match": m.group()})

    for m in URL_PATTERN.finditer(text):
        hits.append({"pattern": "url", "match": m.group()})

    for m in ONION_PATTERN.finditer(text):
        hits.append({"pattern": "onion", "match": m.group()})

    for m in EMAIL_PATTERN.finditer(text):
        hits.append({"pattern": "email", "match": m.group()})

    for m in BASE64_PATTERN.finditer(text):
        blob = m.group()
        if len(blob) >= 20:
            hits.append({"pattern": "base64", "match": blob, "decoded": try_decode_base64(blob)})

    for m in HEX_PATTERN.finditer(text):
        blob = m.group()
        if len(blob) >= 16:
            hits.append({"pattern": "hex", "match": blob, "decoded": try_decode_hex(blob)})

    for m in PEM_PATTERN.finditer(text):
        hits.append({"pattern": "pem", "match": m.group()})

    for m in PRIVKEY_PATTERN.finditer(text):
        hits.append({"pattern": "privkey", "match": m.group()})

    return hits


def extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    """Extract printable ASCII runs of at least *min_len* bytes from raw bytes."""
    out: list[str] = []
    buf: list[str] = []
    for byte in data:
        if 0x20 <= byte < 0x7F:
            buf.append(chr(byte))
        else:
            if len(buf) >= min_len:
                out.append("".join(buf))
            buf = []
    if len(buf) >= min_len:
        out.append("".join(buf))
    return out
