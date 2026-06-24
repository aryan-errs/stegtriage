from __future__ import annotations

import sys

import click
from rich.console import Console

from stegtriage.orchestrator import EXTERNAL_TOOLS, print_tool_table, probe_tools, run_analysis

console = Console()


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("image", required=False, type=click.Path())
@click.option("--wordlist",    type=click.Path(), default=None,
              help="Wordlist for steghide passphrase brute-force.")
@click.option("--password",    default=None,
              help="Single passphrase to try with steghide (skips wordlist).")
@click.option("--outdir",      type=click.Path(), default=None,
              help="Output directory for artifacts (default: ./stegtriage_<basename>/).")
@click.option("--only",        default=None,
              help="Comma-separated subset of modules to run (e.g. lsb,zsteg,strings).")
@click.option("--skip",        default=None,
              help="Comma-separated modules to skip.")
@click.option("--min-str-len", default=6, show_default=True, type=int,
              help="Minimum printable-string length.")
@click.option("--threads",     default=None, type=int,
              help="Max parallel workers (default: CPU count).")
@click.option("--json",        "emit_json", is_flag=True,
              help="Emit machine-readable JSON to stdout instead of the table.")
@click.option("--quiet",       is_flag=True,
              help="Only print the final summary.")
@click.option("-v",            "verbosity", count=True,
              help="Increase verbosity (-v / -vv).")
def main(
    image: str | None,
    wordlist: str | None,
    password: str | None,
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
    summary of findings.  Exits 0 always on completed runs (non-zero only on
    usage / IO errors).

    Run without IMAGE to check which external tools are available.
    """
    if image is None:
        print_tool_table(probe_tools())
        console.print("\n[dim]Tip: pass an IMAGE path to run analysis.[/dim]")
        sys.exit(0)

    run_analysis(
        image,
        outdir=outdir,
        only=only,
        skip=skip,
        min_str_len=min_str_len,
        threads=threads,
        emit_json=emit_json,
        quiet=quiet,
        verbosity=verbosity,
        wordlist=wordlist,
        password=password,
    )


if __name__ == "__main__":
    main()
