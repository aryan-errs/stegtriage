from __future__ import annotations

import time
from pathlib import Path

import numpy as np
from PIL import Image

from stegtriage.models import Finding, ModuleResult
from stegtriage.patterns import FLAG_PATTERNS, scan_text


# ---------------------------------------------------------------------------
# Shared bit-extraction helpers
# ---------------------------------------------------------------------------

def _extract_lsb_bits(arr: np.ndarray, ch_indices: list[int], col_major: bool) -> np.ndarray:
    """Return 1-D uint8 array of LSB bits for the given channels.

    Row-major:    pixels left→right, top→bottom; channels interleaved.
    Column-major: pixels top→bottom, left→right; channels interleaved.
    """
    if col_major:
        # arr.transpose(1,0,2) has shape (w, h, nch); flatten gives col-major order
        view = arr.transpose(1, 0, 2)[:, :, ch_indices]
    else:
        view = arr[:, :, ch_indices]
    return (view & 1).flatten().astype(np.uint8)


def _pack_bytes(bits: np.ndarray, msb_first: bool) -> bytes:
    """Pack bit array → bytes.  Truncates to a multiple of 8 bits."""
    n = (len(bits) // 8) * 8
    if n == 0:
        return b""
    b = bits[:n].reshape(-1, 8).astype(np.uint32)
    w = (np.array([128, 64, 32, 16, 8, 4, 2, 1], dtype=np.uint32)
         if msb_first else
         np.array([1, 2, 4, 8, 16, 32, 64, 128], dtype=np.uint32))
    return bytes((b * w).sum(axis=1).astype(np.uint8))


def _extract_strings(data: bytes, min_len: int = 5) -> list[str]:
    """Extract printable-ASCII runs of at least *min_len* bytes."""
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


# ---------------------------------------------------------------------------
# Sub-stage (a): Bit-plane visual export
# ---------------------------------------------------------------------------

def _export_bit_planes(
    arr: np.ndarray,
    ch_names: list[str],
    out: Path,
) -> dict[str, str]:
    """Export all 8 bit-planes for every channel as greyscale PNGs.

    Returns a mapping  channel_name → path of the LSB (bit-0) plane image.
    """
    lsb_paths: dict[str, str] = {}
    for idx, name in enumerate(ch_names):
        ch = arr[:, :, idx]
        for bit in range(8):
            plane = ((ch >> bit) & 1).astype(np.uint8) * 255
            p = out / f"bitplane_{name}_bit{bit}.png"
            Image.fromarray(plane, mode="L").save(str(p))
        lsb_paths[name] = str(out / f"bitplane_{name}_bit0.png")
    return lsb_paths


# ---------------------------------------------------------------------------
# Sub-stage (b): Multi-ordering LSB bitstream extraction
# ---------------------------------------------------------------------------

_MAX_SCAN_BYTES = 16 * 1024   # inspect first 16 KB per ordering

def _scan_orderings(
    arr: np.ndarray,
    ch_names: list[str],
) -> list[tuple[str, list[dict]]]:
    """Try many LSB orderings; return [(label, hits)] for orderings with hits.

    Orderings tried:
      channels  : each channel solo + all-channels + BGR
      scan order: row-major, column-major
      bit packing: LSB-first, MSB-first
    """
    n_ch = len(ch_names)
    ch_idxs = list(range(n_ch))

    combos: list[tuple[str, list[int]]] = [(name, [i]) for i, name in enumerate(ch_names)]
    combos.append(("+".join(ch_names), ch_idxs))
    if n_ch >= 3:
        combos.append(("BGR", [2, 1, 0]))

    results: list[tuple[str, list[dict]]] = []
    seen_match_keys: set[tuple[str, str]] = set()

    for combo_name, idxs in combos:
        for col_major in (False, True):
            for msb_first in (False, True):
                order = ("col" if col_major else "row") + "-" + ("msb" if msb_first else "lsb")
                label = f"{combo_name}/{order}"
                bits = _extract_lsb_bits(arr, idxs, col_major)
                raw = _pack_bytes(bits, msb_first)[:_MAX_SCAN_BYTES]
                strings = _extract_strings(raw)
                if not strings:
                    continue
                text = "\n".join(strings)
                hits = scan_text(text)
                # Deduplicate across orderings
                new_hits = []
                for h in hits:
                    k = (h["pattern"], h["match"][:80])
                    if k not in seen_match_keys:
                        seen_match_keys.add(k)
                        new_hits.append(h)
                if new_hits:
                    results.append((label, new_hits))

    return results


# ---------------------------------------------------------------------------
# Sub-stage (c): Entropy, structure score, chi-square heuristic
# ---------------------------------------------------------------------------

def _shannon_entropy(bits: np.ndarray) -> float:
    """Shannon entropy of a binary array in bits per symbol (max 1.0)."""
    p1 = float(bits.mean())
    p0 = 1.0 - p1
    if p0 <= 0.0 or p1 <= 0.0:
        return 0.0
    return -(p0 * np.log2(p0) + p1 * np.log2(p1))


def _structure_score(lsb_plane: np.ndarray) -> float:
    """How non-random does the LSB plane look?  Returns [0, 1]; 1 = structured.

    Two metrics combined:
      1. Variance of row-sums vs binomial expectation.
      2. Longest identical-bit run as a fraction of image size.
    The *maximum* is returned so either indicator triggers.
    """
    h, w = lsb_plane.shape
    flat = lsb_plane.flatten()
    n = len(flat)

    # Row-sum variance
    row_sums = lsb_plane.sum(axis=1).astype(float)
    exp_var = w / 4.0
    act_var = float(np.var(row_sums))
    var_score = min(1.0, abs(act_var - exp_var) / max(exp_var, 1.0))

    # Longest identical run (fast via diff)
    diffs = np.diff(flat.astype(np.int8))
    change_pos = np.where(diffs != 0)[0]
    if len(change_pos) == 0:
        max_run = n
    else:
        gaps = np.diff(np.concatenate(([-1], change_pos, [n - 1])))
        max_run = int(gaps.max())
    # Flag if any run exceeds 5 % of the image
    run_score = min(1.0, max_run / max(n * 0.05, 1.0))

    return max(var_score, run_score)


def _chi_square_lsb(channel: np.ndarray) -> tuple[float, float]:
    """Westfeld-Pfitzmann chi-square test for LSB-replacement steganography.

    Under H1 (LSB replaced with random message bits) the adjacent-value pairs
    (2k, 2k+1) are approximately equalised in the histogram.  Under H0 (natural
    image, no stego) they are generally unequal.

    Returns (chi_sq_statistic, embedding_prob_heuristic [0,1]).
    **Heuristic only** — cite as an estimate, not a rigorous p-value.
    """
    hist, _ = np.histogram(channel.flatten(), bins=256, range=(0, 256))
    hist = hist.astype(float)

    chi_sq = 0.0
    n_pairs = 0
    for k in range(128):
        fe, fo = hist[2 * k], hist[2 * k + 1]
        exp = (fe + fo) / 2.0
        if exp > 0:
            chi_sq += (fe - exp) ** 2 / exp + (fo - exp) ** 2 / exp
            n_pairs += 1

    avg = chi_sq / max(n_pairs, 1)
    # Natural images: avg >> 0 → embed_prob → 0
    # Fully-embedded: avg ≈ 0  → embed_prob → 1
    embed_prob = max(0.0, min(1.0, 1.0 - avg / 4.0))
    return chi_sq, embed_prob


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(image_path: str, outdir: str, tool_paths: dict, **opts) -> ModuleResult:
    t0 = time.monotonic()
    path = Path(image_path)
    out = Path(outdir)
    findings: list[Finding] = []
    raw_lines: list[str] = []

    # --- Open image ---
    try:
        orig = Image.open(path)
        mode = "RGBA" if "A" in orig.getbands() else "RGB"
        img = orig.convert(mode)
    except Exception as e:
        return ModuleResult(
            name="lsb", status="error",
            raw_output=str(e), duration_s=time.monotonic() - t0,
        )

    arr = np.array(img, dtype=np.uint8)
    h, w = arr.shape[:2]
    ch_names = list(mode)            # ['R','G','B'] or ['R','G','B','A']
    raw_lines.append(f"Image: {w}×{h} {mode} ({len(ch_names)} channels)")

    # ----------------------------------------------------------------
    # (a) Export all bit-planes
    # ----------------------------------------------------------------
    lsb_paths = _export_bit_planes(arr, ch_names, out)
    n_planes = len(ch_names) * 8
    raw_lines.append(f"(a) Exported {n_planes} bit-plane images → {out}/bitplane_*.png")

    # ----------------------------------------------------------------
    # (b) Multi-ordering LSB bitstream scan
    # ----------------------------------------------------------------
    ordering_results = _scan_orderings(arr, ch_names)
    raw_lines.append(f"(b) Scanned {len(ch_names)*2*2 + 4} orderings; "
                     f"{len(ordering_results)} had pattern hits")

    for ordering_label, hits in ordering_results:
        for hit in hits:
            pattern = hit["pattern"]
            match   = hit["match"]
            decoded = hit.get("decoded")

            if pattern == "flag":
                findings.append(Finding(
                    severity="high",
                    label="Flag in LSB bitstream",
                    detail=f"Ordering {ordering_label}: {match}",
                ))
            elif pattern in ("pem", "privkey"):
                findings.append(Finding(
                    severity="high",
                    label="Key material in LSB bitstream",
                    detail=f"Ordering {ordering_label}: {match[:150]}",
                ))
            elif pattern == "base64":
                detail = f"{ordering_label}: base64 blob ({len(match)} chars)"
                if decoded:
                    detail += f" → {decoded[:80]}"
                findings.append(Finding(
                    severity="medium",
                    label="Base64 in LSB bitstream",
                    detail=detail,
                ))
            elif pattern == "url":
                findings.append(Finding(
                    severity="medium",
                    label="URL in LSB bitstream",
                    detail=f"{ordering_label}: {match}",
                ))

    # ----------------------------------------------------------------
    # (c) Per-channel entropy, structure score, chi-square
    # ----------------------------------------------------------------
    raw_lines.append("(c) Per-channel LSB statistics:")
    for idx, ch_name in enumerate(ch_names):
        ch_data  = arr[:, :, idx]
        lsb_plane = (ch_data & 1)

        entropy    = _shannon_entropy(lsb_plane)
        structure  = _structure_score(lsb_plane)
        chi_sq, embed_prob = _chi_square_lsb(ch_data)

        raw_lines.append(
            f"    {ch_name}: entropy={entropy:.4f}  structure={structure:.4f}"
            f"  χ²={chi_sq:.1f}  embed_prob(heuristic)={embed_prob:.3f}"
        )

        artifact = lsb_paths.get(ch_name)

        # Near-constant LSB plane (solid-colour or near-untouched channel)
        if entropy < 0.10:
            findings.append(Finding(
                severity="medium",
                label=f"Near-constant LSB plane: channel {ch_name}",
                detail=(
                    f"Entropy {entropy:.4f} (max 1.0). "
                    "Solid-colour pixels or nearly untouched LSBs."
                ),
                artifact=artifact,
            ))

        # Structured plane: only meaningful when the channel has *some* real
        # variation (entropy ≥ 0.05) but the bits are non-randomly arranged.
        # entropy < 0.05  → constant/near-constant (covered above; not suspicious)
        # entropy ≥ 0.85  → looks fully random (natural photo; no structure signal)
        if structure > 0.7 and 0.05 <= entropy < 0.85:
            sev = "high" if (structure > 0.9 and entropy < 0.5) else "medium"
            findings.append(Finding(
                severity=sev,
                label=f"Structured LSB plane: channel {ch_name}",
                detail=(
                    f"Structure score {structure:.3f} (0=random, 1=non-random), "
                    f"entropy {entropy:.4f}. "
                    "Long identical-bit runs or abnormal row-sum variance. "
                    "Open the visual plane image."
                ),
                artifact=artifact,
            ))
        elif structure > 0.4 and 0.05 <= entropy < 0.85:
            findings.append(Finding(
                severity="low",
                label=f"Mildly structured LSB plane: channel {ch_name}",
                detail=f"Structure score {structure:.3f}, entropy {entropy:.4f}.",
                artifact=artifact,
            ))

        # Chi-square heuristic — most useful for natural photos; pairs equalised
        # by LSB replacement → embed_prob rises toward 1.0.
        if embed_prob > 0.7:
            findings.append(Finding(
                severity="high" if embed_prob > 0.9 else "medium",
                label=f"LSB-replacement stego likely: channel {ch_name}",
                detail=(
                    f"Chi-square embedding probability (heuristic): {embed_prob:.3f}. "
                    f"χ²={chi_sq:.1f}. Adjacent-value pairs are equalised. "
                    "(Heuristic — false positives possible on smooth gradients.)"
                ),
                artifact=artifact,
            ))

    return ModuleResult(
        name="lsb",
        status="ok",
        findings=findings,
        raw_output="\n".join(raw_lines),
        duration_s=time.monotonic() - t0,
    )
