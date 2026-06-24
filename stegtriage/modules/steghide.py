from __future__ import annotations

import subprocess
import time
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from stegtriage.models import Finding, ModuleResult

# steghide supports only these container formats
_SUPPORTED_EXTS = frozenset({".jpg", ".jpeg", ".bmp", ".wav", ".au"})

_DEFAULT_WORDLIST = Path(__file__).parent.parent / "data" / "default_wordlist.txt"
_DEFAULT_MAX_TRIES = 5000

# Progress bar writes to stderr so it never corrupts --json stdout
_err_console = Console(stderr=True)


def _try_passphrase(
    steghide_bin: str,
    image_path: str,
    passphrase: str,
    out_path: str,
) -> tuple[bool, str]:
    """Run one steghide extract attempt. Returns True on success."""
    # Remove any leftover file from a previous attempt
    try:
        Path(out_path).unlink(missing_ok=True)
    except OSError:
        pass

    try:
        proc = subprocess.run(
            [
                steghide_bin, "extract",
                "-sf", image_path,
                "-p",  passphrase,
                "-xf", out_path,
                "-f",                 # force overwrite
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        stderr_msg = (proc.stdout + proc.stderr).strip()
        if proc.returncode != 0:
            return False, stderr_msg
        out = Path(out_path)
        ok = out.exists() and out.stat().st_size > 0
        return ok, stderr_msg
    except Exception as e:
        return False, str(e)


def run(image_path: str, outdir: str, tool_paths: dict, **opts) -> ModuleResult:
    t0 = time.monotonic()
    path = Path(image_path)
    out = Path(outdir)
    findings: list[Finding] = []
    raw_lines: list[str] = []

    # ── Format check ──────────────────────────────────────────────────────────
    ext = path.suffix.lower()
    if ext not in _SUPPORTED_EXTS:
        return ModuleResult(
            name="steghide",
            status="skipped",
            raw_output=(
                f"steghide only supports JPEG / BMP / WAV / AU; "
                f"'{ext}' is not supported. Skipping."
            ),
        )

    # ── Tool check ────────────────────────────────────────────────────────────
    steghide_bin = tool_paths.get("steghide")
    if not steghide_bin:
        return ModuleResult(
            name="steghide",
            status="skipped",
            raw_output=(
                "steghide not found. "
                "Install: apt install steghide  /  brew install steghide"
            ),
        )

    # ── Build candidate list ──────────────────────────────────────────────────
    max_tries: int = opts.get("max_tries", _DEFAULT_MAX_TRIES)
    direct_password: str | None = opts.get("password")
    wordlist_path: str | None = opts.get("wordlist")

    if direct_password is not None:
        # Single known password — try only that, skip the wordlist entirely
        candidates = [direct_password]
        raw_lines.append(f"Mode: single password supplied directly")
    else:
        if wordlist_path and Path(wordlist_path).exists():
            raw_words = Path(wordlist_path).read_text(encoding="utf-8", errors="replace")
        else:
            raw_words = _DEFAULT_WORDLIST.read_text(encoding="utf-8", errors="replace")

        file_words = [w.strip() for w in raw_words.splitlines() if w.strip()]

        # Always start with empty passphrase and the filename stem (per spec)
        seen_words: set[str] = {"", path.stem}
        candidates: list[str] = ["", path.stem]
        for w in file_words:
            if w not in seen_words:
                seen_words.add(w)
                candidates.append(w)
        candidates = candidates[:max_tries]

    raw_lines.append(
        f"Format: {ext}  |  Candidates: {len(candidates)}  |  Cap: {max_tries}"
    )

    out_file = str(out / f"steghide_{path.stem}")

    # ── Brute-force with progress bar ─────────────────────────────────────────
    found = False
    last_error = ""
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]steghide[/bold cyan]"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=_err_console,
        transient=True,
    ) as progress:
        task = progress.add_task("", total=len(candidates))

        for passphrase in candidates:
            progress.advance(task)
            ok, msg = _try_passphrase(steghide_bin, str(path), passphrase, out_file)
            if msg:
                last_error = msg
            if ok:
                found = True
                display = repr(passphrase) if passphrase else "(empty)"
                raw_lines.append(f"SUCCESS passphrase={display}")
                findings.append(Finding(
                    severity="high",
                    label=f"steghide extraction succeeded",
                    detail=f"Passphrase: {display}. Extracted to {out_file}",
                    artifact=out_file,
                ))
                break

    if not found:
        tried = len(candidates)
        raw_lines.append(f"No passphrase matched ({tried} tried).")
        if last_error:
            raw_lines.append(f"Last steghide error: {last_error}")
        findings.append(Finding(
            severity="info",
            label="steghide: no passphrase cracked",
            detail=(
                f"Tried {tried} passphrase(s) — none succeeded. "
                "Try a larger wordlist with --wordlist rockyou.txt"
            ),
        ))

    return ModuleResult(
        name="steghide",
        status="ok",
        findings=findings,
        raw_output="\n".join(raw_lines),
        duration_s=time.monotonic() - t0,
    )
