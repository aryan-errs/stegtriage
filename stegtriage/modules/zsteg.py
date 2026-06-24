from __future__ import annotations

import subprocess
import time
from pathlib import Path

from stegtriage.models import Finding, ModuleResult
from stegtriage.patterns import FLAG_PATTERNS

# zsteg is only meaningful for these two formats
_SUPPORTED_EXTS = frozenset({".png", ".bmp"})

# Substrings in zsteg content that signal an interesting find
_FILE_TYPES = (
    "jpeg", "jpg", "png", "zip", "gif", "pdf", "elf", "pe32",
    "gzip", "rar", "7-zip", "sqlite", "image data",
)


def _parse_line(line: str) -> tuple[str, str] | None:
    """Split a zsteg output line into (method, content).

    zsteg format:  "b1,r,lsb,xy         .. text: "hello""
    Returns None for header/blank/separator lines.
    """
    if " .. " not in line:
        return None
    method, _, content = line.partition(" .. ")
    return method.strip(), content.strip()


def run(image_path: str, outdir: str, tool_paths: dict, **opts) -> ModuleResult:
    t0 = time.monotonic()
    path = Path(image_path)
    findings: list[Finding] = []

    # ── Format check ──────────────────────────────────────────────────────────
    ext = path.suffix.lower()
    if ext not in _SUPPORTED_EXTS:
        return ModuleResult(
            name="zsteg",
            status="skipped",
            raw_output=(
                f"zsteg only analyses PNG and BMP files; "
                f"'{ext}' is not supported. Skipping."
            ),
        )

    # ── Tool check ────────────────────────────────────────────────────────────
    zsteg_bin = tool_paths.get("zsteg")
    if not zsteg_bin:
        return ModuleResult(
            name="zsteg",
            status="skipped",
            raw_output="zsteg not found. Install: gem install zsteg",
        )

    # ── Run zsteg -a (all methods) ────────────────────────────────────────────
    try:
        proc = subprocess.run(
            [zsteg_bin, "-a", str(path)],
            capture_output=True, text=True, timeout=120,
        )
        raw_output = proc.stdout
        if proc.stderr:
            raw_output += "\n" + proc.stderr
    except Exception as e:
        return ModuleResult(
            name="zsteg", status="error",
            raw_output=str(e), duration_s=time.monotonic() - t0,
        )

    # ── Parse output ──────────────────────────────────────────────────────────
    seen: set[str] = set()

    for line in raw_output.splitlines():
        parsed = _parse_line(line)
        if parsed is None:
            continue
        method, content = parsed

        # Deduplicate on (method, first 80 chars of content)
        key = f"{method}:{content[:80]}"
        if key in seen:
            continue
        seen.add(key)

        # Decide severity
        cl = content.lower()
        has_flag = any(fp.search(content) for fp in FLAG_PATTERNS)
        is_file  = cl.startswith("file:") or any(ft in cl for ft in _FILE_TYPES)
        is_text  = cl.startswith("text:")

        if has_flag:
            findings.append(Finding(
                severity="high",
                label=f"Flag in zsteg output ({method})",
                detail=content,
            ))
        elif is_file:
            findings.append(Finding(
                severity="high",
                label=f"Embedded file signature ({method})",
                detail=content,
            ))
        elif is_text:
            findings.append(Finding(
                severity="medium",
                label=f"Text content in LSB ({method})",
                detail=content,
            ))

    return ModuleResult(
        name="zsteg",
        status="ok",
        findings=findings,
        raw_output=raw_output,
        duration_s=time.monotonic() - t0,
    )
