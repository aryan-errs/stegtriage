from __future__ import annotations

import time
from pathlib import Path

from stegtriage.models import Finding, ModuleResult
from stegtriage.patterns import FLAG_PATTERNS, extract_strings, scan_text


def run(image_path: str, outdir: str, tool_paths: dict, **opts) -> ModuleResult:
    t0 = time.monotonic()
    path = Path(image_path)
    out = Path(outdir)
    min_len: int = opts.get("min_str_len", 6)
    findings: list[Finding] = []

    try:
        data = path.read_bytes()
    except OSError as e:
        return ModuleResult(
            name="strings", status="error",
            raw_output=str(e), duration_s=time.monotonic() - t0,
        )

    strings_list = extract_strings(data, min_len)
    full_dump = "\n".join(strings_list)

    dump_path = out / "strings_dump.txt"
    try:
        dump_path.write_text(full_dump, encoding="utf-8", errors="replace")
    except OSError:
        dump_path = None  # type: ignore[assignment]

    dump_str = str(dump_path) if dump_path else None

    # Scan for high-value patterns
    hits = scan_text(full_dump)
    seen: set[tuple[str, str]] = set()

    for hit in hits:
        pattern = hit["pattern"]
        match = hit["match"]
        key = (pattern, match[:100])
        if key in seen:
            continue
        seen.add(key)

        decoded: str | None = hit.get("decoded")

        if pattern == "flag":
            findings.append(Finding(
                severity="high",
                label="Flag pattern in file strings",
                detail=f"Found: {match}",
                artifact=dump_str,
            ))

        elif pattern in ("pem", "privkey"):
            findings.append(Finding(
                severity="high",
                label="PEM / private-key header in strings",
                detail=match,
                artifact=dump_str,
            ))

        elif pattern == "base64" and len(match) >= 20:
            sev = "info"
            detail = f"Base64 blob ({len(match)} chars)"
            if decoded:
                detail += f" → {decoded[:120]}"
                # Check if decode itself contains a flag
                for fp in FLAG_PATTERNS:
                    if fp.search(decoded):
                        findings.append(Finding(
                            severity="high",
                            label="Flag in decoded base64",
                            detail=f"Decoded: {decoded[:140]}",
                            artifact=dump_str,
                        ))
                        sev = "high"
                        break
                if sev == "info" and "[binary:" in decoded:
                    sev = "medium"
                elif sev == "info":
                    sev = "low"
            findings.append(Finding(
                severity=sev,
                label="Base64 blob in strings",
                detail=detail,
                artifact=dump_str,
            ))

        elif pattern == "hex" and len(match) >= 16:
            detail = f"Hex blob ({len(match)} chars)"
            if decoded:
                detail += f" → {decoded[:80]}"
            findings.append(Finding(
                severity="low",
                label="Hex blob in strings",
                detail=detail,
                artifact=dump_str,
            ))

        elif pattern == "url":
            findings.append(Finding(
                severity="medium",
                label="URL in file strings",
                detail=match,
                artifact=dump_str,
            ))

        elif pattern == "onion":
            findings.append(Finding(
                severity="medium",
                label="Onion address in strings",
                detail=match,
                artifact=dump_str,
            ))

        elif pattern == "email":
            findings.append(Finding(
                severity="low",
                label="Email address in strings",
                detail=match,
                artifact=dump_str,
            ))

    summary = (
        f"Extracted {len(strings_list)} strings (min_len={min_len}) from "
        f"{len(data):,} bytes. {len(findings)} finding(s). "
        f"Full dump: {dump_path}"
    )
    return ModuleResult(
        name="strings",
        status="ok",
        findings=findings,
        raw_output=summary,
        duration_s=time.monotonic() - t0,
    )
