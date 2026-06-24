# StegTriage — Testing Guide

This guide walks through every module with a reproducible test case. Each section explains what to create, what command to run, and exactly what you should see.

---

## Setup

```bash
cd stegtriage
source .venv/bin/activate     # activate the venv created during install
stegtriage                    # confirm the tool runs and shows tool availability
```

All test images are created inline with Python — no external downloads needed.

---

## Module 1 — `fileinfo`: Extension / content mismatch

**What it tests:** fileinfo reads the first 32 magic bytes and compares the real type against the file extension.

### Create the test image

```bash
python3 - << 'EOF'
from PIL import Image
import io, pathlib

buf = io.BytesIO()
Image.new("RGB", (100, 100), (200, 50, 80)).save(buf, format="PNG")
# Save PNG bytes with a .jpg extension
pathlib.Path("test_mismatch.jpg").write_bytes(buf.getvalue())
print("Created test_mismatch.jpg (PNG bytes, .jpg extension)")
EOF
```

### Run

```bash
stegtriage test_mismatch.jpg --only fileinfo
```

### Expected output

```
  fileinfo    ok   ...   1 finding

  ┌──────────┬──────────┬────────────────────────────┬──────────────────────────┐
  │ HIGH     │ fileinfo │ Extension / content mismatch│ Extension is '.jpg' but  │
  │          │          │                             │ magic bytes say 'PNG     │
  │          │          │                             │ image'. Expected: .png   │
  └──────────┴──────────┴────────────────────────────┴──────────────────────────┘
```

**What to confirm:**
- `fileinfo` reports `HIGH`
- The detail says extension is `.jpg` but content is `PNG image`
- No crash

---

## Module 2 — `exif`: Flag in EXIF comment

**What it tests:** exif parses every exiftool tag and promotes flag patterns to HIGH.

### Create the test image

```bash
python3 -c "from PIL import Image; Image.new('RGB',(100,100),(100,180,220)).save('test_exif_flag.jpg', quality=85)"
exiftool -Comment="flag{exif_comment_field}" -overwrite_original test_exif_flag.jpg
```

### Run

```bash
stegtriage test_exif_flag.jpg --only exif
```

### Expected output

```
  exif    ok   ...   2 findings

  HIGH  │ exif │ Flag pattern in EXIF comment   │ Comment: flag{exif_comment_field}
  MED   │ exif │ EXIF comment field: Comment    │ flag{exif_comment_field}
```

**What to confirm:**
- `HIGH` finding with the exact flag text
- The `MEDIUM` finding is the raw comment field (expected duplicate — both fire independently)

---

## Module 2b — `exif`: GPS coordinates

**What it tests:** GPS tags are surfaced as MEDIUM findings.

### Create the test image

```bash
python3 -c "from PIL import Image; Image.new('RGB',(100,100),(200,180,100)).save('test_exif_gps.jpg', quality=85)"
exiftool \
  -GPSLatitude="51.5074" -GPSLatitudeRef=N \
  -GPSLongitude="0.1278" -GPSLongitudeRef=W \
  -overwrite_original test_exif_gps.jpg
```

### Run

```bash
stegtriage test_exif_gps.jpg --only exif
```

### Expected output

```
  exif    ok   ...   5 findings   (all MEDIUM)

  MED  │ exif │ GPS metadata: GPSLatitudeRef   │ North
  MED  │ exif │ GPS metadata: GPSLatitude      │ 51.5074
  MED  │ exif │ GPS metadata: GPSLongitudeRef  │ West
  MED  │ exif │ GPS metadata: GPSLongitude     │ 0.1278
  MED  │ exif │ GPS metadata: GPSPosition      │ 51.5074 N, 0.1278 W
```

**What to confirm:**
- `0` HIGH findings
- All GPS tags appear as `MEDIUM`

---

## Module 3 — `strings`: Flag in raw file bytes

**What it tests:** strings extracts printable-ASCII runs and scans for flag patterns.

### Create the test image

```bash
python3 - << 'EOF'
from PIL import Image
import io, pathlib

buf = io.BytesIO()
Image.new("RGB", (100, 100), (30, 80, 140)).save(buf, format="PNG")
# Append the flag as raw bytes after the valid PNG
payload = b"\nflag{hello_from_strings_module}\n"
pathlib.Path("test_flagstring.png").write_bytes(buf.getvalue() + payload)
print("Created test_flagstring.png with appended flag string")
EOF
```

### Run

```bash
stegtriage test_flagstring.png --only strings
```

### Expected output

```
  strings    ok   ...   1 finding

  HIGH  │ strings │ Flag pattern in file strings │ Found: flag{hello_from_strings_module}
```

**What to confirm:**
- `HIGH` finding with the exact flag
- Full strings dump saved to `stegtriage_test_flagstring/strings_dump.txt`

```bash
grep "flag{" stegtriage_test_flagstring/strings_dump.txt
```

---

## Module 4 — `binwalk`: Native trailing-data check (no binwalk binary needed)

**What it tests:** The native PNG-chunk parser finds data appended after `IEND`.

### Create the test image

```bash
python3 - << 'EOF'
import io, zipfile, pathlib
from PIL import Image

buf = io.BytesIO()
Image.new("RGB", (150, 150), (60, 90, 120)).save(buf, format="PNG")
png = buf.getvalue()
assert b"IEND" in png[-16:]

zip_buf = io.BytesIO()
with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("payload.txt", "flag{zip_appended_after_iend}")

pathlib.Path("test_trailing_zip.png").write_bytes(png + zip_buf.getvalue())
print(f"PNG: {len(png)} bytes  ZIP: {len(zip_buf.getvalue())} bytes")
EOF
```

### Run

```bash
stegtriage test_trailing_zip.png --only binwalk
```

### Expected output

```
  binwalk    ok   ...   N findings

  HIGH  │ binwalk │ Trailing data after PNG EOF (ZIP archive) │ N bytes after PNG end …
  HIGH  │ binwalk │ Binwalk: embedded at 0x… [past container EOF] │ Zip archive data …
  HIGH  │ binwalk │ Binwalk extracted: 1AD.zip   │ Carved file — … bytes
  HIGH  │ binwalk │ Binwalk extracted: secret.txt│ Carved file — … bytes
```

**What to confirm:**
- At least `1 HIGH` finding from the native trailing-data check (fires even if binwalk binary is absent)
- The trailing bytes are identified as a `ZIP archive`
- `trailing_png.bin` artifact created:

```bash
ls stegtriage_test_trailing_zip/trailing_png.bin
file stegtriage_test_trailing_zip/trailing_png.bin  # should say Zip archive
```

- If binwalk is installed, `secret.txt` is also extracted:

```bash
find stegtriage_test_trailing_zip/ -name "payload.txt" -exec cat {} \;
# → flag{zip_appended_after_iend}
```

---

## Module 4b — `fileinfo`: File larger than raw pixels

**What it tests:** For compressed formats (PNG/JPEG), the file should be *smaller* than its raw pixel data. When it's not, fileinfo flags it.

```bash
python3 - << 'EOF'
from PIL import Image
import pathlib, io

# 10×10 solid-colour PNG (very small compressed) then pad with garbage
buf = io.BytesIO()
Image.new("RGB", (10, 10), (100, 100, 100)).save(buf, format="PNG")
png = buf.getvalue()
# Append bytes to make file_size > raw_pixels (10*10*3 = 300 bytes)
pathlib.Path("test_bigfile.png").write_bytes(png + b"\x00" * 500)
print(f"PNG+padding: {len(png)+500} bytes, raw pixels: {10*10*3} bytes")
EOF
stegtriage test_bigfile.png --only fileinfo
```

Expected: `LOW` finding "File larger than raw pixels".

---

## Module 5 — `lsb`: Flag recovered from blue channel

**What it tests:** All three LSB sub-stages — bit-plane export, bitstream extraction, and statistical analysis.

### Create the test image

```bash
python3 - << 'EOF'
import numpy as np
from PIL import Image

arr = np.full((200, 200, 3), [80, 120, 200], dtype=np.uint8)
flag = b"flag{lsb_blue_channel}"

flat_b = arr[:, :, 2].flatten().copy()
for i, byte in enumerate(flag):
    for bit in range(8):
        flat_b[i * 8 + bit] = (flat_b[i * 8 + bit] & 0xFE) | ((byte >> bit) & 1)
arr[:, :, 2] = flat_b.reshape(200, 200)

Image.fromarray(arr, "RGB").save("test_lsb_flag.png")
print("Created test_lsb_flag.png — flag{lsb_blue_channel} in blue channel LSB")
EOF
```

### Run — Stage (a): bit-plane export

```bash
stegtriage test_lsb_flag.png --only lsb
ls stegtriage_test_lsb_flag/bitplane_*.png | wc -l   # should be 24 (3 channels × 8 bits)
```

Open `stegtriage_test_lsb_flag/bitplane_B_bit0.png` in any image viewer. The top-left corner will show a slightly noisy band where the flag bits were written; the rest is solid black (all original LSBs were 0).

### Run — Stage (b): flag recovery

```bash
stegtriage test_lsb_flag.png --only lsb
```

### Expected output

```
  lsb    ok   ...   N findings

  HIGH  │ lsb │ Flag in LSB bitstream │ Ordering B/row-lsb: flag{lsb_blue_channel}
```

**What to confirm:**
- `HIGH` finding with the exact flag text
- Ordering label says `B/row-lsb` (blue channel, row-major, LSB-first — the encoding used)

### Run — Stage (c): statistics (verbose)

```bash
stegtriage test_lsb_flag.png --only lsb -vv 2>&1 | grep "Channel\|entropy\|structure"
```

Expected stats:

```
    R: entropy=0.0000  structure=1.0000  χ²=…  embed_prob(heuristic)=0.000
    G: entropy=0.0000  structure=1.0000  χ²=…  embed_prob(heuristic)=0.000
    B: entropy=0.0153  structure=1.0000  χ²=…  embed_prob(heuristic)=0.000
```

- R and G have `entropy=0` (untouched solid-colour channels)
- B has `entropy≈0.015` (flag bits changed ~224 pixels out of 40,000)
- `embed_prob` is near 0 for all — expected, the chi-square test is designed for natural photos, not solid-colour test images

---

## Regression — Clean image produces no HIGH findings

```bash
python3 - << 'EOF'
import numpy as np
from PIL import Image

# Random-noise image (simulates a natural photo's LSB distribution)
rng = np.random.default_rng(42)
arr = rng.integers(0, 256, (150, 150, 3), dtype=np.uint8)
Image.fromarray(arr, "RGB").save("test_clean_noise.png")
print("Created test_clean_noise.png")
EOF

stegtriage test_clean_noise.png
```

**Expected:** `0 HIGH` findings across all modules. `MEDIUM` from binwalk internal Zlib extraction is normal and expected.

---

## All-modules smoke test

Run the full pipeline against a real CTF-style image (trailing ZIP with flag inside):

```bash
stegtriage test_trailing_zip.png -v
```

You should see all 5 implemented modules run (`fileinfo`, `exif`, `strings`, `binwalk`, `lsb`), and the findings table should include at minimum:

- `HIGH` from **binwalk** — trailing data + extracted files
- `MEDIUM` from **exif** — ExifTool warning about trailer
- `MEDIUM` from **lsb** — near-constant LSB planes (solid-colour image)

```bash
# Confirm the extracted flag text
find stegtriage_test_trailing_zip/ -name "payload.txt" -exec cat {} \;
```

---

## JSON output

```bash
stegtriage test_exif_flag.jpg --json | python3 -m json.tool | head -40
```

Verify the output is valid JSON with the structure:

```json
[
  {
    "name": "exif",
    "status": "ok",
    "findings": [
      { "severity": "high", "label": "Flag pattern in EXIF comment", ... }
    ],
    "duration_s": 0.31
  },
  ...
]
```

---

## `--only` and `--skip` filters

```bash
# Only run fileinfo and strings
stegtriage test_mismatch.jpg --only fileinfo,strings

# Run everything except the slow steghide brute-force
stegtriage challenge.jpg --skip steghide

# Only check for trailing data (fast)
stegtriage big_image.png --only binwalk
```

---

## Verbosity levels

```bash
stegtriage test_trailing_zip.png          # default: findings table only
stegtriage test_trailing_zip.png -v       # + module status lines with timings
stegtriage test_trailing_zip.png -vv      # + full raw output per module
stegtriage test_trailing_zip.png --quiet  # findings table only (no status lines)
```

---

## Graceful degradation (missing tools)

To verify a module is skipped cleanly when its required binary is absent, temporarily hide exiftool:

```bash
PATH_BACKUP=$PATH
export PATH=$(echo $PATH | tr ':' '\n' | grep -v /usr/bin | tr '\n' ':')
stegtriage test_exif_flag.jpg
export PATH=$PATH_BACKUP
```

The `exif` module should show `skipped` with an install hint and no crash.

---

## Quick reference: expected HIGH findings per test image

| Test image | Module | Finding |
|---|---|---|
| `test_mismatch.jpg` | fileinfo | Extension / content mismatch |
| `test_exif_flag.jpg` | exif | Flag pattern in EXIF comment |
| `test_exif_flag.jpg` | strings | Flag pattern in file strings |
| `test_flagstring.png` | strings | Flag pattern in file strings |
| `test_flagstring.png` | binwalk | Trailing data after PNG EOF |
| `test_trailing_zip.png` | binwalk | Trailing data after PNG EOF (ZIP archive) |
| `test_trailing_zip.png` | binwalk | Binwalk extracted: secret.txt |
| `test_lsb_flag.png` | lsb | Flag in LSB bitstream |
| `test_clean.png` / `test_clean_noise.png` | (all) | *(no HIGH findings)* |
