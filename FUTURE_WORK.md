# StegTriage — Future Work

---

## Unfinished from the spec

### `--max-tries` CLI flag

The steghide brute-force cap is hardcoded at 5000 attempts inside `steghide.py`. The spec calls for it to be a user-facing option.

**What to do:**
- Add `--max-tries N` to `cli.py` (default 5000)
- Thread it through `run_analysis` → `opts` → `steghide.run()`
- Document in README options table

---

### Progress bars beyond steghide

The spec says "progress bars" (plural) in step 7. Currently only the steghide brute-force loop has one. Two other slow operations have none:

- **binwalk extraction** on large files can take 10–60 seconds with no feedback
- **LSB orderings scan** on very large images iterates 16+ orderings silently

**What to do:**
- Add a `rich.progress.Progress` spinner to the binwalk subprocess call (indeterminate, since we don't know how long binwalk will take)
- Add a per-ordering progress bar to `_scan_orderings` in `lsb.py` (total = number of orderings)
- Both should write to `stderr` like the steghide bar so `--json` stdout stays clean

---

### `zsteg` artifact extraction

The current `zsteg` module parses text output and promotes findings but never calls `zsteg --extract` or `zsteg -E` to save carved files to `--outdir`. A HIGH "embedded file" finding tells the user something is there but doesn't give them the file.

**What to do:**
- After finding a HIGH file-type finding, re-run zsteg with `-E <method>` for each HIGH method to extract the payload
- Save extracted files to `<outdir>/zsteg_<method>_extracted`
- Add the path as the `Finding.artifact`

---

### Test fixtures for GPS and embedded thumbnail

`tests/make_fixtures.py` has no fixture that plants GPS coordinates or an embedded JPEG thumbnail. Those two exif sub-features are currently exercised only by the manual `test_exif_gps.jpg` image (not committed) and not by the automated suite.

**What to do:**
- Add `_exif_gps()` fixture: create a JPEG, call `exiftool` to embed GPS, save to `fixtures/exif_gps.jpg`
  - Skip fixture generation if `exiftool` is absent (same pattern used in the test file)
- Add `_exif_thumbnail()` fixture: create a JPEG with an embedded thumbnail using `piexif` or `exiftool`
- Add corresponding tests in `test_orchestrator.py` with `@skip_no_exiftool`

---

## Known limitations

### `steghide` brute-force is single-threaded

Each passphrase attempt spawns a subprocess and blocks. Against `rockyou.txt` (14 million entries) at ~50ms per attempt the full wordlist would take days.

**What to do:**
- Use `concurrent.futures.ThreadPoolExecutor` inside the brute-force loop (steghide is I/O-bound, not CPU-bound)
- Worker count: default 4, overridable via `--threads`
- The first thread to succeed sets a `threading.Event`; all other threads check it and exit early
- Progress bar needs to be thread-safe (`Progress.advance` is already thread-safe in rich)

---

### JPEG LSB accuracy

Pillow decompresses JPEG before analysis, so the array passed to the LSB module contains decoded RGB values, not the original compressed bytes. JPEG compression is lossy — it deliberately modifies pixel values during encoding, destroying any LSB payload. Legitimate JPEG LSB stego tools (e.g. JSteg, OutGuess, F5) operate on the DCT coefficients in the compressed domain, not on decoded pixels.

**Consequence:** The LSB module's bitstream extraction and chi-square test are unreliable for JPEG inputs. They may miss real stego and will produce misleading entropy/structure statistics.

**What to do:**
- Add a warning finding at INFO/MEDIUM level when the input is JPEG: "LSB analysis on JPEG is unreliable — JPEG compression destroys pixel-level LSBs. Use steghide or outguess for JPEG stego detection."
- Long term: integrate `jsteg` or parse DCT coefficients via a JPEG parser to detect DCT-domain stego

---

### `strings` module is slow on large files

The Python byte-by-byte loop in `extract_strings` processes ~300MB/s on a modern CPU. A 10MB image takes ~33ms — acceptable — but a 100MB file takes ~330ms and a 1GB file would be over 3 seconds.

**What to do:**
- Replace the loop with `re.findall(rb'[ -~]{N,}', data)` which uses the C regex engine and is 10–50× faster
- The pattern `[ -~]` matches printable ASCII (0x20–0x7E), matching the current behaviour exactly
- Update `extract_strings` in `patterns.py` and keep the same public signature

---

### Chi-square LSB heuristic has high false-positive rate

The Westfeld-Pfitzmann adjacent-pair test reports high embedding probability for:
- Truly random noise images (random pixels have equal pair frequencies by definition)
- Images with smooth gradients (adjacent pixel values naturally differ by 1)
- Solid-colour images with only two values (the test is not calibrated for bimodal histograms)

The current mitigation is labelling it "heuristic" and only firing at MEDIUM. A proper RS (Regular-Singular) analysis from Fridrich et al. (2001) is more robust and less susceptible to these false positives.

**What to do:**
- Implement the RS analysis: classify pixel groups as Regular (R), Singular (S), or Unusable (U) under a flipping function
- The RS estimator gives a reliable embedding rate estimate for natural images
- Keep the chi-square test as a secondary signal; add the RS estimate as a third metric in the raw output
- The RS paper is freely available: Fridrich, Goljan, Du — "Reliable Detection of LSB Steganography" (2001)

---

### No Windows support tested

All subprocess calls use Unix-style binary names (`file`, `binwalk`, etc.) without `.exe` suffixes. `shutil.which` handles this correctly on Windows, but:
- The `file` binary does not exist on Windows
- `steghide` has no official Windows binary
- `zsteg` requires Ruby which has a separate Windows installer
- Path separators in artifact paths shown in the rich table are Unix-style

**What to do:**
- Test the full pipeline on Windows (WSL2 or native)
- Replace hardcoded Unix path assumptions with `Path` objects throughout
- Add Windows install instructions to README for tools that have Windows builds

---

### `binwalk` version sensitivity

Tested and verified on binwalk 2.3.3. The `-C` flag for specifying a custom extraction directory may differ on binwalk 3.x, which restructured its CLI.

**What to do:**
- Detect the installed binwalk version at startup with `binwalk --version`
- Branch on major version: use `-C <dir>` for 2.x, `--directory <dir>` for 3.x
- Add a version-detection step to `probe_tools()` or a separate `_binwalk_flags()` helper

---

## Nice-to-have additions

### `--version` flag

```bash
stegtriage --version   # → stegtriage 0.1.0
```

Add `version=True` to the `@click.command` decorator or use `importlib.metadata.version("stegtriage")`.

---

### Batch mode

```bash
stegtriage *.png
stegtriage /path/to/ctf/images/
```

Accept multiple `IMAGE` arguments or a directory path. Run analysis on each file, aggregate findings, and print a combined table sorted by severity. Most useful in a competition where you have dozens of files to triage quickly.

---

### HTML report

```bash
stegtriage challenge.png --report report.html
```

Generate a self-contained HTML file with:
- Module status timeline
- Findings table (colour-coded)
- Embedded bit-plane images (base64-encoded inline)
- Artifact file list with download links (relative paths)

Useful for sharing results with teammates or for writing up CTF writeups.

---

### `StegSolve`-style channel viewer

```bash
stegtriage challenge.png --only lsb --view
```

After exporting bit-plane images, open them automatically in the system image viewer (`xdg-open` / `open` / `start`). Saves the manual step of navigating to the outdir.

---

### Proper RS analysis for LSB detection

As described under the chi-square limitation above — implement Fridrich et al.'s RS analysis to give a statistically grounded embedding-rate estimate for natural photos. This would be the most impactful single improvement to the LSB module's detection accuracy.
