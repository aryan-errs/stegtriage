from __future__ import annotations

import shutil
import sys

import click
from rich import box
from rich.console import Console
from rich.table import Table

console = Console()

# Maps tool name → human-friendly install hint
EXTERNAL_TOOLS: dict[str, str] = {
    "zsteg":     "gem install zsteg",
    "steghide":  "apt install steghide  /  brew install steghide",
    "exiftool":  "apt install libimage-exiftool-perl  /  brew install exiftool",
    "binwalk":   "apt install binwalk  /  pip install binwalk",
    "strings":   "apt install binutils  /  brew install binutils",
    "file":      "apt install file  /  brew install file",
}


def probe_tools() -> dict[str, str | None]:
    """Return mapping of tool name → resolved path (None if missing)."""
    return {tool: shutil.which(tool) for tool in EXTERNAL_TOOLS}


def _print_tool_table(tool_status: dict[str, str | None]) -> None:
    table = Table(
        title="External Tool Availability",
        box=box.ROUNDED,
        show_lines=False,
        title_style="bold",
    )
    table.add_column("Tool",    style="bold cyan", no_wrap=True)
    table.add_column("Status",  no_wrap=True)
    table.add_column("Path / Install hint")

    for tool, path in tool_status.items():
        if path:
            table.add_row(tool, "[green]available[/green]", path)
        else:
            hint = EXTERNAL_TOOLS.get(tool, "")
            table.add_row(tool, "[red]not found[/red]", f"[dim]{hint}[/dim]")

    console.print(table)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("image", required=False, type=click.Path())
@click.option("--wordlist",     type=click.Path(), default=None,
              help="Wordlist for steghide passphrase brute-force.")
@click.option("--outdir",       type=click.Path(), default=None,
              help="Output directory for artifacts (default: ./stegtriage_<basename>/).")
@click.option("--only",         default=None,
              help="Comma-separated subset of modules to run (e.g. lsb,zsteg,strings).")
@click.option("--skip",         default=None,
              help="Comma-separated modules to skip.")
@click.option("--min-str-len",  default=6, show_default=True, type=int,
              help="Minimum printable-string length.")
@click.option("--threads",      default=None, type=int,
              help="Max parallel workers (default: CPU count).")
@click.option("--json",         "emit_json", is_flag=True,
              help="Emit machine-readable JSON to stdout instead of the table.")
@click.option("--quiet",        is_flag=True,
              help="Only print the final summary.")
@click.option("-v",             "verbosity", count=True,
              help="Increase verbosity (-v / -vv).")
def main(
    image: str | None,
    wordlist: str | None,
    outdir: str | None,
    only: str | None,
    skip: str | None,
    min_str_len: int,
    threads: int | None,
    emit_json: bool,
    quiet: bool,
    verbosity: int,
) -> None:
    """StegTriage — automated steganography / forensics triage for CTF challenges.

    Run a battery of steg/forensics checks against IMAGE and print a ranked
    summary of findings.  Exits 0 always (non-zero only on usage/IO errors).

    Run without IMAGE to just check which external tools are available.
    """
    tool_status = probe_tools()

    if not quiet:
        _print_tool_table(tool_status)

    if image is None:
        console.print("\n[dim]Tip: pass an IMAGE path to run analysis.[/dim]")
        sys.exit(0)

    # Placeholder — analysis modules are wired up in subsequent build steps.
    console.print(f"\n[bold]Target:[/bold] {image}")
    console.print(
        "[yellow]Analysis not yet implemented — "
        "this is the step-1 scaffold.[/yellow]"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
