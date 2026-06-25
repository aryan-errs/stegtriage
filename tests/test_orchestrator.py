"""Integration tests — one per module, each with a planted secret and a clean control."""

from __future__ import annotations

import shutil

import pytest

from tests.make_fixtures import (
    FIXTURES_DIR,
    FLAG_EXIF,
    FLAG_LSB,
    FLAG_STRINGS,
    FLAG_ZIP,
)
from stegtriage.modules.binwalk_mod import run as binwalk_run
from stegtriage.modules.exif import run as exif_run
from stegtriage.modules.fileinfo import run as fileinfo_run
from stegtriage.modules.lsb import run as lsb_run
from stegtriage.modules.strings_mod import run as strings_run

TOOL_PATHS = {t: shutil.which(t) for t in ["file", "exiftool", "binwalk", "zsteg", "steghide"]}

# Convenience markers
skip_no_exiftool = pytest.mark.skipif(
    not shutil.which("exiftool"), reason="exiftool not installed"
)
skip_no_binwalk = pytest.mark.skipif(
    not shutil.which("binwalk"), reason="binwalk not installed"
)


def _highs(result):
    return [f for f in result.findings if f.severity == "high"]


def _has_high(result, label_substr: str) -> bool:
    return any(label_substr.lower() in f.label.lower() for f in _highs(result))


# ---------------------------------------------------------------------------
# fileinfo
# ---------------------------------------------------------------------------

def test_fileinfo_clean_no_high(tmp_path) -> None:
    r = fileinfo_run(str(FIXTURES_DIR / "clean.png"), str(tmp_path), TOOL_PATHS)
    assert r.status == "ok"
    assert _highs(r) == [], f"Unexpected HIGH: {[f.label for f in _highs(r)]}"


def test_fileinfo_detects_ext_mismatch(tmp_path) -> None:
    r = fileinfo_run(str(FIXTURES_DIR / "ext_mismatch.jpg"), str(tmp_path), TOOL_PATHS)
    assert r.status == "ok"
    assert _has_high(r, "mismatch"), f"Expected mismatch finding, got: {[f.label for f in r.findings]}"


# ---------------------------------------------------------------------------
# strings
# ---------------------------------------------------------------------------

def test_strings_clean_no_high(tmp_path) -> None:
    r = strings_run(str(FIXTURES_DIR / "clean.png"), str(tmp_path), TOOL_PATHS)
    assert r.status == "ok"
    assert _highs(r) == [], f"Unexpected HIGH: {[f.label for f in _highs(r)]}"


def test_strings_finds_planted_flag(tmp_path) -> None:
    r = strings_run(str(FIXTURES_DIR / "strings_flag.png"), str(tmp_path), TOOL_PATHS)
    assert r.status == "ok"
    assert any(
        f.severity == "high" and FLAG_STRINGS in f.detail
        for f in r.findings
    ), f"Flag not found. Findings: {[(f.severity, f.detail[:60]) for f in r.findings]}"


def test_strings_dump_written(tmp_path) -> None:
    strings_run(str(FIXTURES_DIR / "strings_flag.png"), str(tmp_path), TOOL_PATHS)
    dump = tmp_path / "strings_dump.txt"
    assert dump.exists(), "strings_dump.txt not written to outdir"
    assert FLAG_STRINGS in dump.read_text()


def test_strings_min_str_len_option(tmp_path) -> None:
    """--min-str-len should be honoured by the strings module."""
    # FLAG_STRINGS is 24 chars; min_str_len=30 should suppress it
    r = strings_run(
        str(FIXTURES_DIR / "strings_flag.png"), str(tmp_path), TOOL_PATHS,
        min_str_len=30,
    )
    flag_highs = [f for f in r.findings if f.severity == "high" and FLAG_STRINGS in f.detail]
    assert flag_highs == [], "Flag should be suppressed at min_str_len > flag length"


# ---------------------------------------------------------------------------
# binwalk  (native trailing-data check — no binary needed)
# ---------------------------------------------------------------------------

def test_binwalk_clean_no_trailing(tmp_path) -> None:
    r = binwalk_run(str(FIXTURES_DIR / "clean.png"), str(tmp_path), TOOL_PATHS)
    assert r.status == "ok"
    trailing_highs = [f for f in _highs(r) if "trailing" in f.label.lower()]
    assert trailing_highs == [], f"False-positive trailing finding: {trailing_highs}"


def test_binwalk_detects_trailing_zip(tmp_path) -> None:
    r = binwalk_run(str(FIXTURES_DIR / "trailing_zip.png"), str(tmp_path), TOOL_PATHS)
    assert r.status == "ok"
    assert any(
        f.severity == "high" and "trailing" in f.label.lower()
        for f in r.findings
    ), "Expected trailing-ZIP HIGH finding"


def test_binwalk_trailing_artifact_written(tmp_path) -> None:
    binwalk_run(str(FIXTURES_DIR / "trailing_zip.png"), str(tmp_path), TOOL_PATHS)
    trail = tmp_path / "trailing_png.bin"
    assert trail.exists(), "trailing_png.bin not written to outdir"
    # Trailing bytes should start with PK (ZIP magic)
    assert trail.read_bytes()[:2] == b"PK"


def test_binwalk_jpeg_append_detected(tmp_path) -> None:
    """Regression: rfind-based JPEG EOF detection missed an appended JPEG.
    The marker-walk _jpeg_eof should find the host image's real end."""
    r = binwalk_run(str(FIXTURES_DIR / "jpeg_append.jpg"), str(tmp_path), TOOL_PATHS)
    assert r.status == "ok"
    assert any(
        f.severity == "high" and "trailing" in f.label.lower()
        for f in r.findings
    ), f"Expected trailing HIGH for appended JPEG. Findings: {[(f.severity, f.label) for f in r.findings]}"


# ---------------------------------------------------------------------------
# exif  (requires exiftool)
# ---------------------------------------------------------------------------

@skip_no_exiftool
def test_exif_clean_no_high(tmp_path) -> None:
    r = exif_run(str(FIXTURES_DIR / "clean.png"), str(tmp_path), TOOL_PATHS)
    assert r.status == "ok"
    assert _highs(r) == [], f"Unexpected HIGH: {[f.label for f in _highs(r)]}"


@skip_no_exiftool
def test_exif_finds_comment_flag(tmp_path) -> None:
    r = exif_run(str(FIXTURES_DIR / "exif_comment.png"), str(tmp_path), TOOL_PATHS)
    assert r.status == "ok"
    assert any(
        f.severity == "high" and "flag" in f.label.lower()
        for f in r.findings
    ), f"Flag not found. Findings: {[(f.severity, f.label) for f in r.findings]}"


def test_exif_skips_without_tool(tmp_path) -> None:
    """Module must degrade gracefully when exiftool is absent."""
    r = exif_run(str(FIXTURES_DIR / "clean.png"), str(tmp_path), {"exiftool": None})
    assert r.status == "skipped"
    assert "exiftool" in r.raw_output.lower()


# ---------------------------------------------------------------------------
# lsb
# ---------------------------------------------------------------------------

def test_lsb_clean_no_high(tmp_path) -> None:
    r = lsb_run(str(FIXTURES_DIR / "clean.png"), str(tmp_path), TOOL_PATHS)
    assert r.status == "ok"
    assert _highs(r) == [], f"Unexpected HIGH on clean image: {[f.label for f in _highs(r)]}"


def test_lsb_finds_embedded_flag(tmp_path) -> None:
    r = lsb_run(str(FIXTURES_DIR / "lsb_blue.png"), str(tmp_path), TOOL_PATHS)
    assert r.status == "ok"
    assert any(
        f.severity == "high" and "flag" in f.label.lower() and FLAG_LSB in f.detail
        for f in r.findings
    ), f"Flag not found. Findings: {[(f.severity, f.label, f.detail[:60]) for f in r.findings]}"


def test_lsb_bit_planes_in_outdir(tmp_path) -> None:
    lsb_run(str(FIXTURES_DIR / "lsb_blue.png"), str(tmp_path), TOOL_PATHS)
    planes = list(tmp_path.glob("bitplane_*.png"))
    assert len(planes) == 24, f"Expected 24 bit-plane files, got {len(planes)}"
