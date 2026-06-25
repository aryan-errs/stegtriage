"""Tests for the lsb module — bit-plane export, bitstream extraction, and stats."""

from __future__ import annotations

import shutil

import numpy as np
import pytest
from PIL import Image

from tests.make_fixtures import FIXTURES_DIR, FLAG_LSB
from stegtriage.modules.lsb import (
    _chi_square_lsb,
    _export_bit_planes,
    _pack_bytes,
    _scan_orderings,
    _shannon_entropy,
    _structure_score,
    run,
)

TOOL_PATHS = {t: shutil.which(t) for t in ["file", "exiftool", "binwalk", "zsteg", "steghide"]}


def _load(name: str) -> np.ndarray:
    return np.array(Image.open(FIXTURES_DIR / name).convert("RGB"), dtype=np.uint8)


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------

def test_entropy_all_zeros() -> None:
    assert _shannon_entropy(np.zeros((10, 10), dtype=np.uint8)) == 0.0


def test_entropy_all_ones() -> None:
    assert _shannon_entropy(np.ones((10, 10), dtype=np.uint8)) == 0.0


def test_entropy_half_half() -> None:
    plane = np.tile([0, 1], 50).reshape(10, 10).astype(np.uint8)
    assert abs(_shannon_entropy(plane) - 1.0) < 0.01


# ---------------------------------------------------------------------------
# Structure score
# ---------------------------------------------------------------------------

def test_structure_constant_plane() -> None:
    """All-zero plane is maximally structured (long identical run)."""
    assert _structure_score(np.zeros((50, 50), dtype=np.uint8)) > 0.9


def test_structure_random_plane() -> None:
    """Random bits should look near-random — low structure score."""
    rng = np.random.default_rng(0)
    plane = rng.integers(0, 2, (100, 100), dtype=np.uint8)
    assert _structure_score(plane) < 0.4


# ---------------------------------------------------------------------------
# Chi-square heuristic
# ---------------------------------------------------------------------------

def test_chi_square_solid_colour_low_prob() -> None:
    """Solid-colour image: histogram is bimodal — chi-square gives low embed_prob."""
    channel = np.full((100, 100), 200, dtype=np.uint8)
    _, prob = _chi_square_lsb(channel)
    assert prob < 0.5


def test_chi_square_equalised_pairs_high_prob() -> None:
    """Artificially equalise adjacent histogram pairs → high embedding probability."""
    # Build array where values 0 and 1, 2 and 3, … appear in equal counts
    vals = np.array(list(range(256)) * 40, dtype=np.uint8)
    rng = np.random.default_rng(1)
    channel = rng.choice(vals, size=(100, 100)).astype(np.uint8)
    _, prob = _chi_square_lsb(channel)
    assert prob > 0.5


# ---------------------------------------------------------------------------
# Bit-plane export
# ---------------------------------------------------------------------------

def test_bit_planes_exported(tmp_path) -> None:
    arr = _load("clean.png")
    paths = _export_bit_planes(arr, ["R", "G", "B"], tmp_path)
    created = list(tmp_path.glob("bitplane_*.png"))
    assert len(created) == 24  # 3 channels × 8 bits
    assert all(k in paths for k in ("R", "G", "B"))
    # Each LSB plane path must exist and be a valid image
    for ch, p in paths.items():
        img = Image.open(p)
        assert img.mode == "L"


# ---------------------------------------------------------------------------
# Bitstream extraction
# ---------------------------------------------------------------------------

def test_lsb_flag_found_in_correct_ordering() -> None:
    arr = _load("lsb_blue.png")
    results = _scan_orderings(arr, ["R", "G", "B"])
    flag_hits = [
        (label, h["match"])
        for label, hits in results
        for h in hits
        if h["pattern"] == "flag"
    ]
    assert flag_hits, "No flag pattern found in any LSB ordering"
    assert any(FLAG_LSB in match for _, match in flag_hits)
    assert any("B" in lbl and "row" in lbl and "lsb" in lbl for lbl, _ in flag_hits)


def test_min_str_len_respected() -> None:
    """FLAG_LSB is 22 chars — min_str_len=25 must suppress it; 5 must find it."""
    arr = _load("lsb_blue.png")
    flag_len = len(FLAG_LSB)  # 22

    strict = _scan_orderings(arr, ["R", "G", "B"], min_str_len=flag_len + 5)
    assert not any(h["pattern"] == "flag" for _, hl in strict for h in hl), \
        "Flag should be suppressed at min_str_len > flag length"

    loose = _scan_orderings(arr, ["R", "G", "B"], min_str_len=5)
    assert any(h["pattern"] == "flag" for _, hl in loose for h in hl), \
        "Flag should be found at min_str_len=5"


def test_pack_bytes_lsb_first() -> None:
    # 'f' = 0x66 = 0b01100110, LSB-first bits: 0,1,1,0,0,1,1,0
    bits = np.array([0, 1, 1, 0, 0, 1, 1, 0], dtype=np.uint8)
    result = _pack_bytes(bits, msb_first=False)
    assert result == b"f"


def test_pack_bytes_msb_first() -> None:
    # MSB-first: [1,1,0,0,1,1,0,0] → 0b11001100 = 0xCC
    bits = np.array([1, 1, 0, 0, 1, 1, 0, 0], dtype=np.uint8)
    result = _pack_bytes(bits, msb_first=True)
    assert result == bytes([0b11001100])


# ---------------------------------------------------------------------------
# Full module — clean control and planted secret
# ---------------------------------------------------------------------------

def test_full_module_clean_no_high(tmp_path) -> None:
    result = run(str(FIXTURES_DIR / "clean.png"), str(tmp_path), TOOL_PATHS)
    assert result.status == "ok"
    highs = [f for f in result.findings if f.severity == "high"]
    assert highs == [], f"Unexpected HIGH on clean image: {[f.label for f in highs]}"


def test_full_module_finds_flag(tmp_path) -> None:
    result = run(str(FIXTURES_DIR / "lsb_blue.png"), str(tmp_path), TOOL_PATHS)
    assert result.status == "ok"
    flag_high = [
        f for f in result.findings
        if f.severity == "high" and "flag" in f.label.lower() and FLAG_LSB in f.detail
    ]
    assert flag_high, f"Flag not found. Findings: {[(f.severity, f.label) for f in result.findings]}"
