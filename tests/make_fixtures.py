"""
Synthesise test fixtures for the stegtriage test suite.

Run directly:   python tests/make_fixtures.py
Auto-called by conftest.py when the fixtures directory is empty.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import numpy as np
from PIL import Image, PngImagePlugin

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Canonical flag values — imported by tests so they stay in sync with fixtures
FLAG_LSB     = "flag{lsb_blue_channel}"
FLAG_EXIF    = "flag{exif_comment_test}"
FLAG_STRINGS = "flag{hidden_in_strings}"
FLAG_ZIP     = "flag{trailing_zip_after_iend}"


def make_all() -> None:
    FIXTURES_DIR.mkdir(exist_ok=True)
    _clean()
    _lsb_blue()
    _exif_comment()
    _trailing_zip()
    _strings_flag()
    _ext_mismatch()
    _jpeg_append()


def _clean() -> None:
    """Random-noise PNG — control image, must yield zero HIGH findings."""
    rng = np.random.default_rng(42)
    arr = rng.integers(0, 256, (100, 100, 3), dtype=np.uint8)
    Image.fromarray(arr, "RGB").save(FIXTURES_DIR / "clean.png")


def _lsb_blue() -> None:
    """PNG with FLAG_LSB embedded in the blue channel LSB, row-major, LSB-first."""
    arr = np.full((100, 100, 3), [80, 120, 200], dtype=np.uint8)
    flag = FLAG_LSB.encode()
    flat_b = arr[:, :, 2].flatten().copy()
    for i, byte in enumerate(flag):
        for bit in range(8):
            flat_b[i * 8 + bit] = (flat_b[i * 8 + bit] & 0xFE) | ((byte >> bit) & 1)
    arr[:, :, 2] = flat_b.reshape(100, 100)
    Image.fromarray(arr, "RGB").save(FIXTURES_DIR / "lsb_blue.png")


def _exif_comment() -> None:
    """PNG with FLAG_EXIF in a tEXt Comment chunk (exiftool reads it as a comment field)."""
    img = Image.new("RGB", (100, 100), (100, 150, 200))
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Comment", FLAG_EXIF)
    img.save(FIXTURES_DIR / "exif_comment.png", pnginfo=meta)


def _trailing_zip() -> None:
    """PNG with a ZIP archive (containing FLAG_ZIP) appended after IEND."""
    buf = io.BytesIO()
    Image.new("RGB", (100, 100), (50, 80, 120)).save(buf, format="PNG")
    png = buf.getvalue()
    assert b"IEND" in png[-16:], "PNG did not end with IEND"

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("secret.txt", FLAG_ZIP)

    (FIXTURES_DIR / "trailing_zip.png").write_bytes(png + zip_buf.getvalue())


def _strings_flag() -> None:
    """PNG with FLAG_STRINGS appended as raw ASCII bytes after IEND."""
    buf = io.BytesIO()
    Image.new("RGB", (100, 100), (60, 90, 130)).save(buf, format="PNG")
    png = buf.getvalue()
    (FIXTURES_DIR / "strings_flag.png").write_bytes(
        png + b"\n" + FLAG_STRINGS.encode() + b"\n"
    )


def _ext_mismatch() -> None:
    """PNG bytes saved with a .jpg extension — triggers fileinfo HIGH."""
    buf = io.BytesIO()
    Image.new("RGB", (100, 100), (200, 50, 80)).save(buf, format="PNG")
    (FIXTURES_DIR / "ext_mismatch.jpg").write_bytes(buf.getvalue())


def _jpeg_append() -> None:
    """JPEG with a second JPEG appended — regression test for the marker-walk fix.

    rfind(FF D9) would land on the appended JPEG's own EOI and suppress the
    trailing-data finding.  The marker-walk _jpeg_eof should find the first
    JPEG's real end and detect the appended bytes.
    """
    buf1 = io.BytesIO()
    Image.new("RGB", (50, 50), (200, 100, 50)).save(buf1, format="JPEG", quality=85)
    buf2 = io.BytesIO()
    Image.new("RGB", (30, 30), (50, 200, 100)).save(buf2, format="JPEG", quality=85)
    (FIXTURES_DIR / "jpeg_append.jpg").write_bytes(buf1.getvalue() + buf2.getvalue())


if __name__ == "__main__":
    make_all()
    print(f"Fixtures written to {FIXTURES_DIR}/")
    for f in sorted(FIXTURES_DIR.iterdir()):
        print(f"  {f.name:<25} {f.stat().st_size:>6} bytes")
