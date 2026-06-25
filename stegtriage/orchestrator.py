from __future__ import annotations

import dataclasses
import json
import os
import shutil
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from stegtriage.models import Finding, ModuleResult

console = Console()

# ---------------------------------------------------------------------------
# External tool registry
# ---------------------------------------------------------------------------

EXTERNAL_TOOLS: dict[str, str] = {
    "zsteg":    "gem install zsteg",
    "steghide": "apt install steghide  /  brew install steghide",
    "exiftool": "apt install libimage-exiftool-perl  /  brew install exiftool",
    "binwalk":  "apt install binwalk  /  pip install binwalk",
    "strings":  "apt install binutils  /  brew install binutils",
    "file":     "apt install file  /  brew install file",
}

# Tool required by each module (None = no external tool needed)
MODULE_REQUIRED_TOOL: dict[str, str | None] = {
    "fileinfo": None,
    "strings":  None,
    "exif":     "exiftool",
    "binwalk":  None,   # native trailing-data check always runs; binwalk binary is optional
    "lsb":      None,
    "zsteg":    "zsteg",
    "steghide": "steghide",
}

# Ordered list of all modules (grows with each build step)
ALL_MODULES: list[str] = ["fileinfo", "exif", "strings", "binwalk", "lsb", "zsteg", "steghide"]

# ---------------------------------------------------------------------------
# Severity rendering
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[str, int] = {"high": 0, "medium": 1, "low": 2, "info": 3}
_SEVERITY_STYLE: dict[str, str] = {
    "high":   "bold red",
    "medium": "yellow",
    "low":    "cyan",
    "info":   "dim white",
}


# ---------------------------------------------------------------------------
# Tool probing
# ---------------------------------------------------------------------------

def probe_tools() -> dict[str, str | None]:
    """Return mapping of tool name → resolved path (None if missing)."""
    return {tool: shutil.which(tool) for tool in EXTERNAL_TOOLS}


def print_tool_table(tool_status: dict[str, str | None]) -> None:
    table = Table(
        title="External Tool Availability",
        box=box.ROUNDED,
        show_lines=False,
        title_style="bold",
    )
    table.add_column("Tool",   style="bold cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Path / Install hint")
    for tool, path in tool_status.items():
        if path:
            table.add_row(tool, "[green]available[/green]", path)
        else:
            hint = EXTERNAL_TOOLS.get(tool, "")
            table.add_row(tool, "[red]not found[/red]", f"[dim]{hint}[/dim]")
    console.print(table)


# ---------------------------------------------------------------------------
# Module loader (lazy import to keep registry simple and avoid circulars)
# ---------------------------------------------------------------------------

def _load_module_fn(name: str) -> Callable | None:
    if name == "fileinfo":
        from stegtriage.modules.fileinfo import run
        return run
    if name == "exif":
        from stegtriage.modules.exif import run
        return run
    if name == "strings":
        from stegtriage.modules.strings_mod import run
        return run
    if name == "binwalk":
        from stegtriage.modules.binwalk_mod import run
        return run
    if name == "lsb":
        from stegtriage.modules.lsb import run
        return run
    if name == "zsteg":
        from stegtriage.modules.zsteg import run
        return run
    if name == "steghide":
        from stegtriage.modules.steghide import run
        return run
    return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_analysis(
    image_path: str,
    *,
    outdir: str | None = None,
    only: str | None = None,
    skip: str | None = None,
    min_str_len: int = 6,
    threads: int | None = None,
    emit_json: bool = False,
    quiet: bool = False,
    verbosity: int = 0,
    wordlist: str | None = None,
    password: str | None = None,
) -> list[ModuleResult]:
    path = Path(image_path)
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] file not found: {image_path}")
        raise SystemExit(1)

    resolved_outdir = outdir or f"stegtriage_{path.stem}"
    Path(resolved_outdir).mkdir(parents=True, exist_ok=True)

    tool_paths = probe_tools()

    # Resolve which modules to run
    modules_to_run = list(ALL_MODULES)
    if only:
        wanted = {m.strip() for m in only.split(",")}
        modules_to_run = [m for m in ALL_MODULES if m in wanted]
    if skip:
        skip_set = {m.strip() for m in skip.split(",")}
        modules_to_run = [m for m in modules_to_run if m not in skip_set]

    if not quiet and not emit_json:
        console.print(f"\n[bold]Analyzing:[/bold] {image_path}")
        console.print(f"[dim]Artifacts → {resolved_outdir}/[/dim]")
        console.print()

    opts = {"min_str_len": min_str_len, "verbosity": verbosity, "wordlist": wordlist, "password": password}
    max_workers = max(1, threads or os.cpu_count() or 4)

    results: list[ModuleResult] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(modules_to_run) or 1)) as pool:
        futures = {
            pool.submit(
                _run_module, name, image_path, resolved_outdir, tool_paths, opts
            ): name
            for name in modules_to_run
        }
        for future in as_completed(futures):
            results.append(future.result())

    # Restore display order
    order = {name: i for i, name in enumerate(ALL_MODULES)}
    results.sort(key=lambda r: order.get(r.name, 999))

    if emit_json:
        print(json.dumps([dataclasses.asdict(r) for r in results], indent=2))
    else:
        _render_summary(results, verbosity=verbosity, show_header=not quiet)

    return results


# ---------------------------------------------------------------------------
# Module runner (error boundary + raw-output persistence)
# ---------------------------------------------------------------------------

def _run_module(
    name: str,
    image_path: str,
    outdir: str,
    tool_paths: dict[str, str | None],
    opts: dict,
) -> ModuleResult:
    # Skip if required external tool is absent
    required = MODULE_REQUIRED_TOOL.get(name)
    if required and not tool_paths.get(required):
        hint = EXTERNAL_TOOLS.get(required, "see docs")
        return ModuleResult(
            name=name,
            status="skipped",
            raw_output=f"Required tool '{required}' not found. Install: {hint}",
        )

    fn = _load_module_fn(name)
    if fn is None:
        return ModuleResult(
            name=name,
            status="skipped",
            raw_output="Module not yet implemented.",
        )

    t0 = time.monotonic()
    try:
        result = fn(image_path, outdir, tool_paths, **opts)
    except Exception:
        result = ModuleResult(
            name=name,
            status="error",
            raw_output=traceback.format_exc(),
            duration_s=time.monotonic() - t0,
        )

    # Persist raw output alongside artifacts
    if result.raw_output:
        raw_path = Path(outdir) / f"{name}_raw.txt"
        try:
            raw_path.write_text(result.raw_output, encoding="utf-8", errors="replace")
        except OSError:
            pass

    return result


# ---------------------------------------------------------------------------
# Summary renderer
# ---------------------------------------------------------------------------

def _render_summary(
    results: list[ModuleResult],
    *,
    verbosity: int,
    show_header: bool = True,
) -> None:
    if show_header:
        for r in results:
            if r.status == "ok":
                status_tag = "[green]ok[/green]"
            elif r.status == "skipped":
                status_tag = "[yellow]skipped[/yellow]"
            else:
                status_tag = "[bold red]error[/bold red]"

            n = len(r.findings)
            skip_reason = ""
            if r.status == "skipped" and r.raw_output:
                skip_reason = f"  [dim]({r.raw_output.splitlines()[0]})[/dim]"

            console.print(
                f"  [bold cyan]{r.name:<14}[/bold cyan]"
                f" {status_tag:<8}"
                f"  [dim]{r.duration_s:.2f}s"
                f"  {n} finding{'s' if n != 1 else ''}[/dim]"
                f"{skip_reason}"
            )
            if verbosity >= 2 and r.status != "skipped" and r.raw_output:
                console.rule(f"[dim]{r.name} raw output[/dim]")
                console.print(f"[dim]{r.raw_output[:4000]}[/dim]")

        console.print()

    # Collect and sort findings
    tagged: list[tuple[str, Finding]] = [
        (r.name, f) for r in results for f in r.findings
    ]
    tagged.sort(key=lambda x: _SEVERITY_ORDER.get(x[1].severity, 99))

    if not tagged:
        console.print("[dim]No findings.[/dim]")
        return

    table = Table(
        title="Findings",
        box=box.ROUNDED,
        show_lines=True,
        title_style="bold",
        expand=False,
    )
    table.add_column("Severity", no_wrap=True, min_width=8)
    table.add_column("Module",   no_wrap=True, min_width=10)
    table.add_column("Label",    min_width=24)
    table.add_column("Detail",   max_width=58)
    table.add_column("Artifact", max_width=38, overflow="fold")

    for mod_name, f in tagged:
        style = _SEVERITY_STYLE.get(f.severity, "")
        table.add_row(
            Text(f.severity.upper(), style=style),
            mod_name,
            f.label,
            f.detail,
            f.artifact or "",
        )

    console.print(table)
    _render_next_steps(tagged)


def _render_next_steps(tagged: list[tuple[str, Finding]]) -> None:
    tips: list[str] = []
    seen: set[str] = set()

    def add(tip: str) -> None:
        if tip not in seen:
            tips.append(tip)
            seen.add(tip)

    for _, f in tagged:
        lo = f.label.lower()

        if f.severity == "high" and "mismatch" in lo:
            add(
                "Extension/type mismatch — rename to the real extension "
                "and open with the appropriate tool (unzip, binwalk, etc.)."
            )
        if f.severity == "high" and "flag" in lo:
            add(f"Flag pattern found → {f.detail[:100]}")
        if f.severity == "high" and "base64" in lo:
            add("Base64 payload decoded to something interesting — inspect the decoded content.")
        if f.severity == "high" and ("pem" in lo or "private key" in lo):
            add("Private key material found — extract and check what service it belongs to.")
        if f.artifact and any(f.artifact.endswith(ext) for ext in (".zip", ".gz", ".tar")):
            add(f"Embedded archive → try: unzip {f.artifact}")
        if f.severity == "high" and "trailing" in lo:
            hint = f" ({f.artifact})" if f.artifact else ""
            add(f"Trailing data after container EOF{hint} — try: binwalk -e or unzip on the original file.")
        if "gps" in lo:
            add("GPS coordinates in EXIF — check for location leakage or position-encoded hints.")
        if "thumbnail" in lo and f.artifact:
            add(f"Embedded thumbnail extracted → {f.artifact} — compare visually with the main image.")
        if "lsb" in lo and "plane" in lo and f.artifact:
            add(f"Structured LSB plane → open {f.artifact} visually, or try: zsteg -a <image>")
        if "steghide" in lo and "no passphrase" in lo:
            add(
                "steghide brute-force failed — try a larger wordlist: "
                "stegtriage <image> --wordlist /usr/share/wordlists/rockyou.txt"
            )
        if f.severity == "high" and "steghide extraction succeeded" in lo and f.artifact:
            add(f"steghide extracted payload → {f.artifact} — inspect it for the flag.")
        if f.severity == "high" and "embedded file" in lo:
            add(
                "zsteg found an embedded file signature — "
                "try: zsteg --extract <image> to carve it out."
            )
        if "url" in lo and f.severity in ("medium", "high"):
            add(f"URL found in file data → {f.detail[:80]}")
        if "near-constant lsb" in lo:
            add(
                "Near-constant LSB plane — solid-colour image may hide data in LSB. "
                "Check the bitplane images and try: zsteg -a <image>"
            )

    if tips:
        console.print()
        console.print("[bold]Next steps:[/bold]")
        for tip in tips:
            console.print(f"  [green]▶[/green] {tip}")
