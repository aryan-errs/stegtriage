# StegTriage

Automated steganography and forensics triage for CTF challenges and digital forensics practice.

Point it at an image, get back a ranked table of everything suspicious — hidden files, flag strings, LSB stego, EXIF secrets, trailing data — in seconds.

> **Scope:** StegTriage is a **detection and extraction** tool for CTF and defensive forensics work. It does not embed or hide data. Never use it against images you do not own or have explicit permission to analyse.

---

## Installation

### 1. Python package

```bash
git clone <repo>
cd stegtriage
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Requires Python 3.10+. Python dependencies (`pillow`, `numpy`, `rich`, `click`) are installed automatically.

### 2. External tools

StegTriage shells out to several binaries. **All are optional** — the tool degrades gracefully when any are absent, marking those modules as `SKIPPED` with an install hint.

| Tool | What it's used for | Linux (apt) | macOS (brew) | Other |
|---|---|---|---|---|
| `exiftool` | EXIF / metadata extraction | `apt install libimage-exiftool-perl` | `brew install exiftool` | [exiftool.org](https://exiftool.org) |
| `binwalk` | Embedded file signatures + extraction | `apt install binwalk` | `brew install binwalk` | `pip install binwalk` |
| `zsteg` | PNG/BMP LSB stego (all methods) | — | — | `gem install zsteg` |
| `steghide` | JPEG/BMP/WAV steghide extraction | `apt install steghide` | `brew install steghide` | — |
| `file` | Magic-byte type identification | `apt install file` | built-in | — |
| `strings` | (fallback, not required) | `apt install binutils` | built-in | — |

Check which tools are available on your system:

```bash
stegtriage          # prints tool availability table
```

---

## Usage

```
stegtriage IMAGE [OPTIONS]
```

### Basic

```bash
# Run all modules against an image
stegtriage challenge.png

# Only run specific modules
stegtriage challenge.png --only lsb,strings,binwalk

# Skip a module
stegtriage challenge.png --skip steghide

# Save artifacts to a custom directory
stegtriage challenge.png --outdir /tmp/ctf_work/
```

### Verbosity

```bash
stegtriage challenge.png          # summary table
stegtriage challenge.png -v       # show module status timings
stegtriage challenge.png -vv      # dump raw tool output per module
stegtriage challenge.png --quiet  # findings table only, no status lines
```

### Scripting

```bash
# Machine-readable JSON (feeds into jq, other tools)
stegtriage challenge.png --json | jq '.[] | select(.findings | length > 0)'

# Pipe HIGH findings only
stegtriage challenge.png --json \
  | jq '[.[].findings[] | select(.severity=="high")]'
```

### Strings options

```bash
# Lower the minimum string length (catches short flags)
stegtriage challenge.png --min-str-len 4

# Use a larger wordlist for steghide brute-force
stegtriage challenge.png --wordlist /usr/share/wordlists/rockyou.txt
```

### Parallelism

```bash
# Limit thread pool (useful on slow machines or to reduce I/O)
stegtriage challenge.png --threads 2
```

### All options

| Option | Default | Description |
|---|---|---|
| `IMAGE` | (required) | Path to the image or file to analyse |
| `--wordlist PATH` | bundled list | Wordlist for steghide passphrase brute-force |
| `--outdir PATH` | `./stegtriage_<name>/` | Where extracted artifacts are written |
| `--only MODULES` | all | Comma-separated list of modules to run |
| `--skip MODULES` | none | Comma-separated list of modules to skip |
| `--min-str-len N` | `6` | Minimum printable-string run length |
| `--threads N` | CPU count | Max parallel workers |
| `--json` | off | Emit JSON to stdout instead of the rich table |
| `--quiet` | off | Print findings table only, suppress status lines |
| `-v` / `-vv` | off | Increase verbosity (tool output shown at `-vv`) |

Exit code is **always 0** on a completed run ("nothing found" is a valid result). Non-zero only on usage or I/O errors.

---

## Modules

All modules run in parallel. Each writes its full raw output and any carved artifacts to `--outdir`; the terminal only shows matched findings.

### `fileinfo`
Reads the first 32 bytes to identify the file type from magic bytes, then cross-checks against the file extension. Also runs `file` if available.

**Flags as HIGH:** extension/content mismatch (e.g. a `.jpg` that is actually a PNG or ZIP).  
**Flags as MEDIUM:** suspicious aspect ratios (> 50:1), file larger than its raw uncompressed pixels.

### `exif`
Runs `exiftool -a -G1 -s` and parses every tag. Extracts embedded thumbnails to `--outdir`.

**Flags as HIGH:** flag patterns inside comment fields, flags decoded from base64-encoded fields.  
**Flags as MEDIUM:** GPS coordinates, comment/UserComment/ImageDescription fields, base64-looking field values, ExifTool warnings (e.g. "Trailer data after PNG IEND").  
**Flags as LOW:** embedded thumbnail extracted, high-entropy / non-printable fields.  
**Flags as INFO:** software/creator tags.

> Requires `exiftool`. Skipped gracefully if absent.

### `strings`
Pure-Python printable-ASCII extractor (no external binary needed). Scans the raw file bytes for runs of printable characters and applies pattern matching.

**Flags as HIGH:** flag patterns (`flag{…}`, `CTF{…}`, `picoCTF{…}`, `HTB{…}`, etc.), PEM/private-key headers, flags decoded from base64 blobs.  
**Flags as MEDIUM:** URLs, onion addresses, base64 blobs that decode to binary magic bytes.  
**Flags as LOW:** email addresses, hex blobs, base64 blobs.

Full strings dump saved to `<outdir>/strings_dump.txt`.

### `binwalk`
Two independent sub-checks:

1. **Native trailing-data check** (always runs, no binary needed): parses PNG chunks forward to find `IEND`, uses `rfind` for JPEG `FFD9` and GIF `0x3B` trailer. Any bytes after the container's declared end are a **HIGH** finding; the payload is identified by magic bytes (ZIP, gzip, RAR, 7-Zip, PDF, …) and saved as `trailing_<fmt>.bin`.

2. **Binwalk binary scan** (if `binwalk` is installed): runs `binwalk -e -C <outdir>` for signature detection and file extraction. Signatures at offsets past the container EOF are **HIGH**; signatures within normal file structure (e.g. PNG IDAT zlib) are **MEDIUM**.

> The native trailing-data check always fires regardless of whether `binwalk` is installed.

### `lsb`
Native Pillow + NumPy analysis. No external binary.

**(a) Bit-plane export:** Every bit plane (bits 0–7) for every channel (R, G, B, A) is rendered as a greyscale image and saved to `--outdir`. Visual LSB stego often becomes immediately obvious when you open `bitplane_B_bit0.png`.

**(b) Bitstream extraction:** The LSB bits are extracted in multiple orderings (row-major / column-major, RGB / BGR, LSB-first / MSB-first, per-channel and combined) and each byte stream is scanned for flag patterns, URLs, base64 blobs, and key material. A match in any ordering is a **HIGH** finding.

**(c) Statistical analysis:**
- *Shannon entropy* per channel (0 = constant, 1 = fully random). Near-constant channels (entropy < 0.05) are flagged MEDIUM.
- *Structure score* (variance of row-sums, longest identical-bit run). Non-trivial structure (entropy 0.05–0.85, structure > 0.7) is flagged MEDIUM/HIGH.
- *Chi-square / sample-pairs heuristic* (Westfeld-Pfitzmann style): adjacent pixel-value pairs (2k, 2k+1) are compared. LSB replacement equalises them; a high embedding-probability score is flagged MEDIUM. **Heuristic only** — useful on natural photos, not solid-colour images.

### `zsteg` *(coming in step 5)*
Runs `zsteg -a` against PNG and BMP files. Parses output for text/file/flag lines and promotes them to HIGH findings.

> Requires `zsteg` (`gem install zsteg`). Skipped for non-PNG/BMP inputs.

### `steghide` *(coming in step 5)*
Tries empty passphrase first, then brute-forces using `--wordlist`. Stops on first success. Progress bar shown during brute-force.

> Requires `steghide`. Skipped for unsupported formats (only JPEG/BMP/WAV/AU).

---

## Output

### Terminal (default)

```
Analyzing: challenge.png
Artifacts → stegtriage_challenge/

  fileinfo       ok       0.08s  0 findings
  exif           ok       0.31s  1 finding
  strings        ok       0.01s  0 findings
  binwalk        ok       0.94s  3 findings
  lsb            ok       0.09s  1 finding

╭──────────┬─────────┬──────────────────────────┬──────────────────────────────╮
│ Severity │ Module  │ Label                    │ Detail                       │
├──────────┼─────────┼──────────────────────────┼──────────────────────────────┤
│ HIGH     │ binwalk │ Trailing data after PNG… │ 149 bytes after PNG end …    │
│ HIGH     │ lsb     │ Flag in LSB bitstream    │ Ordering B/row-lsb: flag{…}  │
│ MEDIUM   │ exif    │ ExifTool warning         │ Trailer data after PNG IEND  │
╰──────────┴─────────┴──────────────────────────┴──────────────────────────────╯

Next steps:
  ▶ Trailing data after container EOF → try: binwalk -e or unzip on the file
  ▶ Flag pattern found → Ordering B/row-lsb: flag{lsb_blue_channel_stego}
```

### JSON (`--json`)

```bash
stegtriage challenge.png --json | jq .
```

```json
[
  {
    "name": "lsb",
    "status": "ok",
    "findings": [
      {
        "severity": "high",
        "label": "Flag in LSB bitstream",
        "detail": "Ordering B/row-lsb: flag{lsb_blue_channel_stego}",
        "artifact": null
      }
    ],
    "raw_output": "...",
    "duration_s": 0.09
  }
]
```

### Artifacts directory

Every piece of raw tool output and every carved file lands in `--outdir`:

```
stegtriage_challenge/
  fileinfo_raw.txt          ← raw output from fileinfo module
  exif_raw.txt              ← full exiftool output
  strings_dump.txt          ← every printable string extracted
  binwalk_raw.txt           ← binwalk signature table
  trailing_png.bin          ← bytes after PNG IEND (if any)
  bitplane_R_bit0.png       ← LSB plane images (R/G/B/A × bits 0–7)
  bitplane_G_bit0.png
  bitplane_B_bit0.png
  binwalk_extracted/        ← files carved by binwalk
    _challenge.png.extracted/
      1AD.zip
      secret.txt
```

---

## Severity levels

| Severity | Meaning |
|---|---|
| **HIGH** | Strong signal — flag pattern found, known-malicious signature, extension mismatch, file appended past container EOF |
| **MEDIUM** | Worth investigating — GPS data, comment fields, base64 blobs, ExifTool warnings, near-constant LSB planes |
| **LOW** | Informational but notable — email addresses, hex blobs, aspect ratio, embedded thumbnail |
| **INFO** | Context only — software tags, image metadata |

---

## Supported file types

| Format | fileinfo | exif | strings | binwalk | lsb | zsteg | steghide |
|---|---|---|---|---|---|---|---|
| PNG | ✓ | ✓ | ✓ | ✓ (native EOF) | ✓ | ✓ | ✗ |
| JPEG | ✓ | ✓ | ✓ | ✓ (native EOF) | ✓ | ✗ | ✓ |
| BMP | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| GIF | ✓ | ✓ | ✓ | ✓ (native EOF) | ✓ | ✗ | ✗ |
| WAV/AU | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ |
| Any file | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |

---

## Project layout

```
stegtriage/
  pyproject.toml
  README.md
  stegtriage/
    cli.py            ← click entry point
    orchestrator.py   ← tool probing, thread pool, summary renderer
    models.py         ← Finding and ModuleResult dataclasses
    patterns.py       ← shared regexes + base64/hex decode helpers
    modules/
      fileinfo.py
      exif.py
      strings_mod.py
      binwalk_mod.py
      lsb.py
      zsteg.py        ← stub, step 5
      steghide.py     ← stub, step 5
    data/
      default_wordlist.txt
  tests/
    fixtures/
    test_lsb.py
    test_patterns.py
    test_orchestrator.py
```
