from __future__ import annotations

import subprocess
import time
from pathlib import Path

from stegtriage.models import Finding, ModuleResult

# (magic prefix, human label, set of expected extensions)
_MAGIC_SIGS: list[tuple[bytes, str, frozenset[str]]] = [
    (b"\x89PNG\r\n\x1a\n", "PNG image",          frozenset({".png"})),
    (b"\xff\xd8\xff",       "JPEG image",         frozenset({".jpg", ".jpeg", ".jfif"})),
    (b"GIF87a",             "GIF image",          frozenset({".gif"})),
    (b"GIF89a",             "GIF image",          frozenset({".gif"})),
    (b"BM",                 "BMP image",          frozenset({".bmp"})),
    (b"RIFF",               "RIFF container",     frozenset({".wav", ".avi", ".webp"})),
    (b"PK\x03\x04",         "ZIP archive",        frozenset({".zip", ".jar", ".docx", ".xlsx", ".pptx", ".odt"})),
    (b"PK\x05\x06",         "ZIP archive",        frozenset({".zip"})),
    (b"\x1f\x8b",           "gzip archive",       frozenset({".gz", ".tgz"})),
    (b"Rar!\x1a\x07",       "RAR archive",        frozenset({".rar"})),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive",     frozenset({".7z"})),
    (b"%PDF",               "PDF document",       frozenset({".pdf"})),
    (b"MZ",                 "PE executable",      frozenset({".exe", ".dll", ".sys"})),
    (b"\x7fELF",            "ELF executable",     frozenset({".elf", ""})),
    (b"II*\x00",            "TIFF image",         frozenset({".tif", ".tiff"})),
    (b"MM\x00*",            "TIFF image",         frozenset({".tif", ".tiff"})),
]

# Formats where the on-disk file is normally *smaller* than raw pixel data
_COMPRESSED_FORMATS = frozenset({"PNG", "JPEG", "GIF", "WEBP"})


def _detect_magic(header: bytes) -> tuple[str, frozenset[str]] | None:
    for prefix, label, exts in _MAGIC_SIGS:
        if header.startswith(prefix):
            return label, exts
    return None


def run(image_path: str, outdir: str, tool_paths: dict, **opts) -> ModuleResult:
    t0 = time.monotonic()
    path = Path(image_path)
    findings: list[Finding] = []
    raw_lines: list[str] = []

    # --- Read header ---
    try:
        header = path.read_bytes()[:32]
        file_size = path.stat().st_size
    except OSError as e:
        return ModuleResult(
            name="fileinfo", status="error",
            raw_output=str(e), duration_s=time.monotonic() - t0,
        )

    raw_lines.append(f"File: {path.name}  ({file_size:,} bytes)")
    raw_lines.append(f"Magic header: {header[:8].hex()}")

    # --- Native magic detection ---
    ext = path.suffix.lower()
    detected = _detect_magic(header)

    if detected:
        type_label, valid_exts = detected
        raw_lines.append(f"Detected type: {type_label}")
        if ext and ext not in valid_exts:
            findings.append(Finding(
                severity="high",
                label="Extension / content mismatch",
                detail=(
                    f"Extension is '{ext}' but magic bytes say '{type_label}'. "
                    f"Expected extension(s): {', '.join(sorted(valid_exts))}"
                ),
            ))
    else:
        raw_lines.append(f"Detected type: unknown (no magic match for {header[:4].hex()})")
        findings.append(Finding(
            severity="info",
            label="Unknown file type",
            detail=f"Magic bytes {header[:4].hex()} matched no known signature.",
        ))

    # --- `file` command (optional) ---
    file_bin = tool_paths.get("file")
    if file_bin:
        try:
            proc = subprocess.run(
                [file_bin, "--", str(path)],
                capture_output=True, text=True, timeout=10,
            )
            file_out = proc.stdout.strip()
            raw_lines.append(f"`file`: {file_out}")
        except Exception as e:
            raw_lines.append(f"`file` failed: {e}")

    # --- Pillow image analysis ---
    try:
        from PIL import Image

        with Image.open(path) as img:
            w, h = img.size
            fmt = img.format or "unknown"
            mode = img.mode
            n_channels = len(img.getbands())

        raw_lines.append(f"Image: {fmt} {w}×{h} {mode} ({n_channels} channel(s))")

        # Absurd aspect ratio
        if w > 0 and h > 0:
            ratio = max(w, h) / min(w, h)
            if ratio > 50:
                findings.append(Finding(
                    severity="medium",
                    label="Suspicious aspect ratio",
                    detail=f"Dimensions {w}×{h} → {ratio:.0f}:1 ratio. Unusual shapes can conceal data.",
                ))

        # File size vs. pixel count
        raw_pixel_bytes = w * h * n_channels
        if raw_pixel_bytes > 0:
            if fmt in _COMPRESSED_FORMATS and file_size > raw_pixel_bytes:
                findings.append(Finding(
                    severity="low",
                    label="File larger than raw pixels",
                    detail=(
                        f"{fmt} is {file_size:,} B on disk but only {raw_pixel_bytes:,} B of raw pixel data. "
                        "Compressed formats should be smaller — possible appended data."
                    ),
                ))
            elif fmt not in _COMPRESSED_FORMATS and file_size > raw_pixel_bytes * 2 + 1024:
                findings.append(Finding(
                    severity="low",
                    label="File much larger than expected",
                    detail=(
                        f"{fmt} is {file_size:,} B; expected ~{raw_pixel_bytes:,} B uncompressed. "
                        "Possible appended data."
                    ),
                ))

    except Exception as e:
        raw_lines.append(f"Pillow: {e}")
        if not detected:
            findings.append(Finding(
                severity="info",
                label="Could not parse as image",
                detail=str(e),
            ))

    return ModuleResult(
        name="fileinfo",
        status="ok",
        findings=findings,
        raw_output="\n".join(raw_lines),
        duration_s=time.monotonic() - t0,
    )
