from __future__ import annotations

import struct
import subprocess
import time
from pathlib import Path

from stegtriage.models import Finding, ModuleResult


# ---------------------------------------------------------------------------
# Native container-EOF finders
# ---------------------------------------------------------------------------

def _png_eof(data: bytes) -> int | None:
    """Return offset just past PNG IEND+CRC, or None if data is not a PNG."""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    pos = 8  # skip 8-byte signature
    while pos + 12 <= len(data):  # minimum chunk = 4+4+0+4
        length = struct.unpack_from(">I", data, pos)[0]
        chunk_type = data[pos + 4: pos + 8]
        end = pos + 4 + 4 + length + 4  # len_field + type + data + crc
        if chunk_type == b"IEND":
            return end
        if end <= pos:  # guard against corrupt/zero-length loops
            break
        pos = end
    return None


def _jpeg_eof(data: bytes) -> int | None:
    """Return offset just past JPEG EOI (FF D9), or None if not JPEG."""
    if not data.startswith(b"\xff\xd8\xff"):
        return None
    idx = data.rfind(b"\xff\xd9")
    return idx + 2 if idx != -1 else None


def _gif_eof(data: bytes) -> int | None:
    """Return offset just past GIF trailer (0x3B), or None if not GIF."""
    if not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
        return None
    idx = data.rfind(b"\x3b")
    return idx + 1 if idx != -1 else None


def _container_eof(data: bytes) -> tuple[str, int] | None:
    """Return (format_name, eof_offset) for the first recognised container."""
    for fn, name in ((_png_eof, "PNG"), (_jpeg_eof, "JPEG"), (_gif_eof, "GIF")):
        eof = fn(data)
        if eof is not None:
            return name, eof
    return None


_TRAILING_MAGIC: list[tuple[bytes, str]] = [
    (b"PK\x03\x04",        "ZIP archive"),
    (b"PK\x05\x06",        "ZIP archive (empty)"),
    (b"\x1f\x8b",          "gzip"),
    (b"Rar!\x1a\x07",      "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c","7-Zip archive"),
    (b"%PDF",               "PDF document"),
    (b"\x89PNG",            "PNG image"),
    (b"\xff\xd8\xff",       "JPEG image"),
    (b"GIF8",               "GIF image"),
    (b"\x7fELF",            "ELF executable"),
    (b"MZ",                 "PE executable"),
]


def _identify_magic(blob: bytes) -> str:
    for magic, label in _TRAILING_MAGIC:
        if blob.startswith(magic):
            return label
    return ""


def _native_trailing_check(
    data: bytes, out: Path
) -> tuple[list[Finding], int | None]:
    """Detect bytes after known container end.

    Returns (findings, eof_offset).  eof_offset is None if the format was not
    recognised, or the container had no trailing bytes.
    """
    info = _container_eof(data)
    if info is None:
        return [], None

    fmt, eof = info
    if eof >= len(data):
        return [], eof  # clean — nothing past EOF

    trailing = data[eof:]
    magic_label = _identify_magic(trailing)
    type_hint = f" ({magic_label})" if magic_label else ""

    trail_path = out / f"trailing_{fmt.lower()}.bin"
    try:
        trail_path.write_bytes(trailing)
        artifact = str(trail_path)
    except OSError:
        artifact = None

    finding = Finding(
        severity="high",
        label=f"Trailing data after {fmt} EOF{type_hint}",
        detail=(
            f"{len(trailing):,} bytes after {fmt} end at offset 0x{eof:x}. "
            f"First bytes: {trailing[:8].hex()}"
        ),
        artifact=artifact,
    )
    return [finding], eof


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(image_path: str, outdir: str, tool_paths: dict, **opts) -> ModuleResult:
    t0 = time.monotonic()
    path = Path(image_path)
    out = Path(outdir)
    findings: list[Finding] = []
    raw_lines: list[str] = []

    # --- Read file once ---
    try:
        data = path.read_bytes()
    except OSError as e:
        return ModuleResult(
            name="binwalk", status="error",
            raw_output=str(e), duration_s=time.monotonic() - t0,
        )

    # --- 1. Native trailing-data check (always, regardless of binwalk) ---
    native_findings, eof_offset = _native_trailing_check(data, out)
    findings.extend(native_findings)

    # --- 2. Binwalk (if installed) ---
    binwalk_bin = tool_paths.get("binwalk")
    if binwalk_bin:
        extract_dir = out / "binwalk_extracted"
        extract_dir.mkdir(exist_ok=True)
        before: set[Path] = set(extract_dir.rglob("*"))

        try:
            # binwalk 2.x: -e for extraction, -C to specify output directory
            # Note: binwalk 2.x does not support '--' end-of-options separator
            proc = subprocess.run(
                [binwalk_bin, "-e", "-C", str(extract_dir), str(path.resolve())],
                capture_output=True, text=True, timeout=120,
            )
            bw_out = proc.stdout
            if proc.returncode not in (0, 1) and proc.stderr:
                bw_out += "\nSTDERR: " + proc.stderr
            raw_lines.append(bw_out)
        except Exception as e:
            raw_lines.append(f"binwalk error: {e}")
            bw_out = ""

        # Parse the signature table
        # Lines look like:  "292           0x124           Zip archive data, ..."
        seen_offsets: set[int] = set()
        for line in bw_out.splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[0].isdigit() and parts[1].startswith("0x"):
                offset = int(parts[0])
                description = parts[2].strip()
                if offset == 0 or offset in seen_offsets:
                    continue  # offset 0 is the container itself
                seen_offsets.add(offset)

                is_past_eof = eof_offset is not None and offset >= eof_offset
                sev = "high" if is_past_eof else "medium"
                label = f"Binwalk: embedded at 0x{offset:x}"
                if is_past_eof:
                    label += " [past container EOF]"
                findings.append(Finding(
                    severity=sev,
                    label=label,
                    detail=description[:150],
                ))

        # List newly-extracted files as artifacts.
        # binwalk names extracted files by their hex offset in the source file
        # (e.g. "1AD.zip" was carved from offset 0x1AD).  We use that to decide
        # severity: files from offsets past the container EOF are HIGH; files
        # from within the container (e.g. PNG IDAT zlib at 0x29) are MEDIUM.
        after: set[Path] = set(extract_dir.rglob("*"))
        for carved in sorted(after - before):
            if not carved.is_file():
                continue
            # Try to read the offset from the filename stem
            import re as _re
            m = _re.match(r'^([0-9A-Fa-f]+)', carved.stem)
            if m:
                file_offset = int(m.group(1), 16)
                is_past = eof_offset is not None and file_offset >= eof_offset
            else:
                # Filename has no hex prefix (e.g. "secret.txt" inside a ZIP)
                # Treat as HIGH only if there was trailing data at all
                is_past = bool(native_findings)
            findings.append(Finding(
                severity="high" if is_past else "medium",
                label=f"Binwalk extracted: {carved.name}",
                detail=f"Carved file — {carved.stat().st_size:,} bytes",
                artifact=str(carved),
            ))

    raw_output = "\n".join(raw_lines) if raw_lines else "Native trailing-data check only (binwalk not used)."
    return ModuleResult(
        name="binwalk",
        status="ok",
        findings=findings,
        raw_output=raw_output,
        duration_s=time.monotonic() - t0,
    )
