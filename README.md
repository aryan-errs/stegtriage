# StegTriage

Automated steganography and forensics triage for CTF challenges and digital forensics practice.

Point it at an image, get back a ranked table of everything suspicious — hidden files, flag strings, LSB stego, EXIF secrets, trailing data — in seconds.

> **Scope:** StegTriage is a **detection and extraction** tool for CTF and defensive forensics work. It does not embed or hide data. Never use it against images you do not own or have explicit permission to analyse.

---

## Installation

### 1. Python package

```bash
git clone git@github.com:aryan-errs/stegtriage.git
cd stegtriage

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -e .
```

Requires **Python 3.10+**. Python dependencies (`pillow`, `numpy`, `rich`, `click`) are installed automatically.

### 2. External tools

StegTriage shells out to several binaries. **All are optional** — the tool degrades gracefully when any are absent, marking those modules as `SKIPPED` with an install hint. Never crashes because a tool is missing.

| Tool       | Used for                              | Linux (apt)                          | macOS (brew)            | Other                                |
| ---------- | ------------------------------------- | ------------------------------------ | ----------------------- | ------------------------------------ |
| `exiftool` | EXIF / metadata extraction            | `apt install libimage-exiftool-perl` | `brew install exiftool` | [exiftool.org](https://exiftool.org) |
| `binwalk`  | Embedded file signatures + extraction | `apt install binwalk`                | `brew install binwalk`  | `pip install binwalk`                |
| `zsteg`    | PNG/BMP LSB stego (all orderings)     | —                                    | —                       | `gem install zsteg` (requires Ruby)  |
| `steghide` | JPEG/BMP/WAV passphrase extraction    | `apt install steghide`               | `brew install steghide` | —                                    |
| `file`     | Magic-byte type identification        | `apt install file`                   | built-in                | —                                    |

Check which tools are available on your system:

```bash
stegtriage          # no image → prints tool availability table
```

### 3. Run the tests

```bash
pip install -e ".[dev]"
python -m pytest
```

The test suite is self-contained — it synthesises all required fixture images at session start so no real challenge files are needed.

---

## Usage

```
stegtriage IMAGE [OPTIONS]
```

### Basic

```bash
# Full analysis
stegtriage challenge.png

# Only run specific modules
stegtriage challenge.png --only lsb,strings,binwalk

# Skip a slow module
stegtriage challenge.png --skip steghide

# Custom artifact directory
stegtriage challenge.png --outdir /tmp/ctf_work/
```

### steghide passphrase

```bash
# Try a single known passphrase
stegtriage challenge.bmp --only steghide --password "DUEDILIGENCE"

# Brute-force with a custom wordlist
stegtriage challenge.bmp --only steghide --wordlist /usr/share/wordlists/rockyou.txt
```

### Verbosity

```bash
stegtriage challenge.png           # default: findings table
stegtriage challenge.png -v        # + module status lines with timing
stegtriage challenge.png -vv       # + full raw tool output per module
stegtriage challenge.png --quiet   # findings table only, no status lines
```

### Machine-readable JSON

```bash
# Full JSON output (safe for --json | jq piping)
stegtriage challenge.png --json

# All HIGH findings across all modules
stegtriage challenge.png --json \
  | jq '[.[].findings[] | select(.severity=="high")]'

# Modules that found something
stegtriage challenge.png --json \
  | jq '.[] | select(.findings | length > 0) | {module: .name, count: (.findings | length)}'

# Feed into another tool
stegtriage challenge.png --json > report.json
```

### All options

| Option            | Default                | Description                                           |
| ----------------- | ---------------------- | ----------------------------------------------------- |
| `IMAGE`           | (required)             | Path to the image / file to analyse                   |
| `--wordlist PATH` | bundled 65-entry list  | Wordlist for steghide passphrase brute-force          |
| `--password TEXT` | —                      | Single known passphrase for steghide (skips wordlist) |
| `--outdir PATH`   | `./stegtriage_<name>/` | Where artifacts are written                           |
| `--only MODULES`  | all                    | Comma-separated list of modules to run                |
| `--skip MODULES`  | none                   | Comma-separated list of modules to skip               |
| `--min-str-len N` | `6`                    | Minimum printable-string run length                   |
| `--threads N`     | CPU count              | Max parallel workers                                  |
| `--json`          | off                    | Emit JSON to stdout instead of the rich table         |
| `--quiet`         | off                    | Findings table only, suppress status lines            |
| `-v` / `-vv`      | off                    | Increase verbosity (`-vv` dumps raw tool output)      |

Exit code is **always 0** on a completed run ("nothing found" is a valid result). Non-zero only on usage or I/O errors.

---

## Modules

All modules run in parallel. Each writes its full raw output and any carved artifacts to `--outdir`; the terminal shows only matched findings.

### `fileinfo`

Reads the first 32 bytes natively to identify the file type, cross-checks against the extension, then optionally runs `file`.

- **HIGH** — extension/content mismatch (e.g. a `.jpg` that is actually a ZIP)
- **MEDIUM** — suspicious aspect ratio (> 50:1), file larger than its raw uncompressed pixels
- **INFO** — image dimensions and detected type

### `exif`

Runs `exiftool -a -G1 -s` and parses every tag. Extracts embedded thumbnails to `--outdir`.

- **HIGH** — flag pattern inside a comment/description field; flag decoded from a base64-encoded field
- **MEDIUM** — GPS coordinates, comment/UserComment/ImageDescription, base64-looking values, ExifTool warnings
- **LOW** — embedded thumbnail extracted (compare with main image), high-entropy fields
- **INFO** — software/creator tags

> Requires `exiftool`. Skipped gracefully if absent.

### `strings`

Pure-Python printable-ASCII extractor — no external binary needed. Scans every raw byte of the file and runs the results through the pattern matcher.

- **HIGH** — flag pattern (`flag{…}`, `CTF{…}`, `picoCTF{…}`, `HTB{…}`, etc.), PEM/private-key headers, flags decoded from base64
- **MEDIUM** — URLs, onion addresses, base64 blobs that decode to binary magic
- **LOW** — email addresses, hex blobs

Full strings dump saved to `<outdir>/strings_dump.txt`.

### `binwalk`

Two independent checks — the native one always runs regardless of whether `binwalk` is installed:

1. **Native trailing-data check:** walks PNG chunks forward to the `IEND` marker; for JPEG, parses the marker chain to the real `FF D9` EOI (not `rfind`, so an appended JPEG is correctly detected); for GIF, seeks to the `0x3B` trailer. Any bytes after the container's declared end are **HIGH**; the payload is identified by magic (ZIP, gzip, RAR, 7-Zip, PDF, JPEG, …) and saved as `trailing_<fmt>.bin`.

2. **Binwalk binary:** runs `binwalk -e -C <outdir>` for signature detection and file extraction. Signatures at offsets past the container EOF are **HIGH**; signatures inside normal file structure (e.g. PNG IDAT zlib) are **MEDIUM**.

### `lsb`

Native Pillow + NumPy — no external binary.

**(a) Bit-plane export:** Every bit plane (bits 0–7) for every channel (R, G, B, A) is saved to `--outdir` as a greyscale image. LSB stego often becomes visible immediately when you open `bitplane_B_bit0.png`.

**(b) Bitstream extraction:** LSB bits are extracted in multiple orderings (row-major / column-major × RGB / BGR × LSB-first / MSB-first, per-channel and combined) and each stream is scanned for flags, URLs, base64, and key material. A match is **HIGH** and reports the exact ordering used.

**(c) Statistical analysis:**

- _Shannon entropy_ — 0 = constant (solid colour), 1 = fully random. Near-constant channels (entropy < 0.05) flagged **MEDIUM**.
- _Structure score_ — long identical-bit runs + row-sum variance deviation. Non-trivial structure in a non-constant channel flagged **MEDIUM/HIGH**.
- _Chi-square heuristic_ — Westfeld-Pfitzmann adjacent-pair test. High embedding probability flagged **MEDIUM**. Most useful on natural photos; not meaningful on solid-colour images. Cited as a heuristic.

### `zsteg`

Runs `zsteg -a` (all orderings) against PNG and BMP files. Parses every output line:

- **HIGH** — flag pattern in text content; recognised file-type signature (JPEG, ZIP, ELF, …)
- **MEDIUM** — any other readable text content

> Requires `zsteg` (`gem install zsteg`). Automatically skipped for non-PNG/BMP inputs.

### `steghide`

Attempts extraction from JPEG, BMP, WAV, and AU files.

1. Tries the empty passphrase and the filename stem first.
2. With `--password TEXT`, tries that single passphrase and stops.
3. Otherwise iterates the wordlist (`--wordlist PATH`; default: bundled 65-entry CTF list), stopping on first success.

Capped at `5000` attempts. Progress bar shown during brute-force (written to stderr so `--json` stdout stays clean).

- **HIGH** — extraction succeeded; extracted file saved as artifact
- **INFO** — no passphrase cracked (suggests a larger wordlist)

> Requires `steghide`. Automatically skipped for unsupported formats.

---

## Output

### Terminal (default)

```
Analyzing: challenge.png
Artifacts → stegtriage_challenge/

  fileinfo       ok       0.08s  0 findings
  exif           ok       0.31s  1 finding
  strings        ok       0.01s  0 findings
  binwalk        ok       0.94s  5 findings
  lsb            ok       0.09s  1 finding
  zsteg          skipped           (Required tool 'zsteg' not found…)
  steghide       skipped           (steghide only supports JPEG/BMP…)

╭──────────┬─────────┬──────────────────────────┬──────────────────────────────┐
│ Severity │ Module  │ Label                    │ Detail                       │
├──────────┼─────────┼──────────────────────────┼──────────────────────────────┤
│ HIGH     │ binwalk │ Trailing data after PNG  │ 149 bytes after PNG end …    │
│ HIGH     │ lsb     │ Flag in LSB bitstream    │ Ordering B/row-lsb: flag{…}  │
│ MEDIUM   │ exif    │ ExifTool warning         │ Trailer data after PNG IEND  │
╰──────────┴─────────┴──────────────────────────┴──────────────────────────────┘

Next steps:
  ▶ Trailing data after container EOF → inspect trailing_png.bin
  ▶ Flag pattern found → Ordering B/row-lsb: flag{lsb_blue_channel}
```

### JSON (`--json`)

All console output is suppressed; only valid JSON is written to stdout.

```bash
stegtriage challenge.png --json | jq .
```

```json
[
  {
    "name": "binwalk",
    "status": "ok",
    "findings": [
      {
        "severity": "high",
        "label": "Trailing data after PNG EOF (ZIP archive)",
        "detail": "149 bytes after PNG end at offset 0x1ad. First bytes: 504b0304…",
        "artifact": "stegtriage_challenge/trailing_png.bin"
      }
    ],
    "raw_output": "…",
    "duration_s": 0.94
  },
  {
    "name": "lsb",
    "status": "ok",
    "findings": [
      {
        "severity": "high",
        "label": "Flag in LSB bitstream",
        "detail": "Ordering B/row-lsb: flag{lsb_blue_channel}",
        "artifact": null
      }
    ],
    "raw_output": "…",
    "duration_s": 0.09
  }
]
```

### Artifacts directory

Every module's raw output and every carved/extracted file lands in `--outdir`:

```
stegtriage_challenge/
  fileinfo_raw.txt          ← magic bytes, file command output, image info
  exif_raw.txt              ← full exiftool output
  strings_dump.txt          ← every printable string extracted from the file
  strings_raw.txt           ← strings module summary
  binwalk_raw.txt           ← binwalk signature table
  lsb_raw.txt               ← per-channel entropy / structure / chi-square stats
  trailing_png.bin          ← bytes appended after container EOF
  bitplane_R_bit0.png       ← LSB plane images (channels × bits 0–7 = up to 32 files)
  bitplane_G_bit0.png
  bitplane_B_bit0.png
  binwalk_extracted/
    _challenge.extracted/
      1AD.zip
      secret.txt
```

---

## Severity levels

| Level      | Meaning                                                                                                                                        |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| **HIGH**   | Strong signal — flag found, known-malicious signature, extension mismatch, data past container EOF, steghide extraction succeeded              |
| **MEDIUM** | Worth investigating — GPS data, comment fields, base64 blobs, ExifTool warnings, near-constant or structured LSB planes, text content in zsteg |
| **LOW**    | Informational — email addresses, hex blobs, embedded thumbnail, unusual aspect ratio                                                           |
| **INFO**   | Context only — software tags, steghide wordlist exhausted                                                                                      |

---

## Supported formats

| Format   | fileinfo | exif | strings | binwalk      | lsb | zsteg | steghide |
| -------- | -------- | ---- | ------- | ------------ | --- | ----- | -------- |
| PNG      | ✓        | ✓    | ✓       | ✓ native EOF | ✓   | ✓     | ✗        |
| JPEG     | ✓        | ✓    | ✓       | ✓ native EOF | ✓   | ✗     | ✓        |
| BMP      | ✓        | ✓    | ✓       | ✓            | ✓   | ✓     | ✓        |
| GIF      | ✓        | ✓    | ✓       | ✓ native EOF | ✓   | ✗     | ✗        |
| WAV / AU | ✓        | ✓    | ✓       | ✓            | ✗   | ✗     | ✓        |
| Any file | ✓        | ✓    | ✓       | ✓            | ✗   | ✗     | ✗        |

---

## Project layout

```
stegtriage/
  pyproject.toml
  README.md
  TESTING.md
  stegtriage/
    cli.py            ← click entry point
    orchestrator.py   ← tool probing, thread pool, summary renderer
    models.py         ← Finding and ModuleResult dataclasses
    patterns.py       ← shared regexes, base64/hex decoders, extract_strings
    modules/
      fileinfo.py
      exif.py
      strings_mod.py
      binwalk_mod.py
      lsb.py
      zsteg.py
      steghide.py
    data/
      default_wordlist.txt
  tests/
    conftest.py
    make_fixtures.py
    fixtures/           ← generated at test time, not committed
    test_patterns.py
    test_lsb.py
    test_orchestrator.py
```
