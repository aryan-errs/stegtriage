from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

from stegtriage.models import Finding, ModuleResult
from stegtriage.patterns import BASE64_PATTERN, FLAG_PATTERNS, try_decode_base64

# Tags always surfaced as findings
_GPS_RE = re.compile(r"GPS(?!VersionID)", re.IGNORECASE)

_COMMENT_TAGS = frozenset({
    "comment", "usercomment", "imagedescription", "xpcomment",
    "xpsubject", "caption", "captionabstract", "headline",
    "description", "subject",
})
_THUMBNAIL_TAGS = frozenset({
    "thumbnailimage", "previewimage", "otherimage",
    "jpeginterchangeformat",
})
_SOFTWARE_TAGS = frozenset({
    "software", "creatortool", "producer", "generator",
    "creator", "writingapp", "tool",
})

# exiftool -G1 -s output:  [Group]   TagName   : Value
_LINE_RE = re.compile(r"^\[(.+?)\]\s+(\S+)\s+:\s*(.*)")


def run(image_path: str, outdir: str, tool_paths: dict, **opts) -> ModuleResult:
    t0 = time.monotonic()
    path = Path(image_path)
    out = Path(outdir)
    exiftool = tool_paths.get("exiftool")
    findings: list[Finding] = []

    if not exiftool:
        return ModuleResult(
            name="exif", status="skipped",
            raw_output="exiftool not found. "
                       "Install: apt install libimage-exiftool-perl / brew install exiftool",
        )

    # --- Run exiftool -a -G1 -s ---
    try:
        proc = subprocess.run(
            [exiftool, "-a", "-G1", "-s", str(path)],
            capture_output=True, text=True, timeout=30,
        )
        raw_output = proc.stdout
    except Exception as e:
        return ModuleResult(
            name="exif", status="error",
            raw_output=str(e), duration_s=time.monotonic() - t0,
        )

    has_thumbnail = False
    seen: set[tuple] = set()

    # Surface exiftool's own Warning lines as findings
    for line in raw_output.splitlines():
        wm = _LINE_RE.match(line)
        if wm and wm.group(2).lower() == "warning":
            warn_text = wm.group(3).strip()
            k = ("warning", warn_text[:80])
            if k not in seen:
                seen.add(k)
                findings.append(Finding(
                    severity="medium",
                    label="ExifTool warning",
                    detail=warn_text,
                ))

    for line in raw_output.splitlines():
        m = _LINE_RE.match(line)
        if not m:
            continue
        _group, tag, value = m.group(1), m.group(2), m.group(3).strip()
        tag_lower = tag.lower()

        # GPS coords / ref tags
        if _GPS_RE.search(tag):
            k = ("gps", tag)
            if k not in seen:
                seen.add(k)
                findings.append(Finding(
                    severity="medium",
                    label=f"GPS metadata: {tag}",
                    detail=value,
                ))

        # Comment / description fields
        if tag_lower in _COMMENT_TAGS:
            k = ("comment", tag_lower, value[:80])
            if k not in seen:
                seen.add(k)
                findings.append(Finding(
                    severity="medium",
                    label=f"EXIF comment field: {tag}",
                    detail=value[:300],
                ))
                for fp in FLAG_PATTERNS:
                    for fm in fp.finditer(value):
                        findings.append(Finding(
                            severity="high",
                            label="Flag pattern in EXIF comment",
                            detail=f"{tag}: {fm.group()}",
                        ))

        # Thumbnail presence — extracted below
        if tag_lower in _THUMBNAIL_TAGS:
            has_thumbnail = True

        # Software / tool tags
        if tag_lower in _SOFTWARE_TAGS:
            k = ("sw", tag_lower, value[:60])
            if k not in seen:
                seen.add(k)
                findings.append(Finding(
                    severity="info",
                    label=f"Software tag: {tag}",
                    detail=value,
                ))

        # Base64-looking value
        bm = BASE64_PATTERN.search(value)
        if bm and len(bm.group()) >= 20:
            blob = bm.group()
            k = ("b64", blob[:40])
            if k not in seen:
                seen.add(k)
                decoded = try_decode_base64(blob)
                detail = f"{tag}: {blob[:80]}"
                if decoded:
                    detail += f" → {decoded[:100]}"
                    for fp in FLAG_PATTERNS:
                        if fp.search(decoded):
                            findings.append(Finding(
                                severity="high",
                                label="Flag in base64-encoded EXIF field",
                                detail=f"{tag} decoded: {decoded[:200]}",
                            ))
                findings.append(Finding(
                    severity="medium",
                    label=f"Base64-encoded EXIF field: {tag}",
                    detail=detail,
                ))

        # Long / high-entropy / non-printable value
        if len(value) > 80:
            non_print = sum(1 for c in value if not c.isprintable())
            if non_print / len(value) > 0.25:
                k = ("entropy", tag)
                if k not in seen:
                    seen.add(k)
                    pct = non_print * 100 // len(value)
                    findings.append(Finding(
                        severity="low",
                        label=f"High-entropy EXIF field: {tag}",
                        detail=f"{len(value)} chars, {non_print} non-printable ({pct}%)",
                    ))

    # --- Extract embedded thumbnail ---
    if has_thumbnail:
        thumb_path = out / f"thumbnail_{path.stem}.jpg"
        try:
            tp = subprocess.run(
                [exiftool, "-b", "-ThumbnailImage", str(path)],
                capture_output=True, timeout=15,
            )
            if tp.returncode == 0 and tp.stdout:
                thumb_path.write_bytes(tp.stdout)
                findings.append(Finding(
                    severity="low",
                    label="Embedded thumbnail extracted",
                    detail=f"{len(tp.stdout):,} bytes — compare with main image.",
                    artifact=str(thumb_path),
                ))
        except Exception as e:
            findings.append(Finding(
                severity="info",
                label="Thumbnail extraction failed",
                detail=str(e),
            ))

    return ModuleResult(
        name="exif",
        status="ok",
        findings=findings,
        raw_output=raw_output,
        duration_s=time.monotonic() - t0,
    )
