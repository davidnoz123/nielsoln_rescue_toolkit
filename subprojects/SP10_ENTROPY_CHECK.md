# SP10 — ENTROPY_CHECK

**Status:** 📋 Planned
**Phase:** 2 — Engineering foundations
**Priority:** 10

## Goal

Identify packed or obfuscated files using Shannon entropy and simple binary
heuristics, without needing YARA or external tools.

## Scope

1. **Entropy calculation** — Shannon entropy over the first 64 KB of each file.
   Values above 7.2 bits/byte suggest compression or encryption (packers,
   encoded payloads).

2. **PE header checks** — for `.exe`/`.dll` files, parse the DOS and PE headers
   (stdlib `struct`) to check:
   - Section count
   - Section names (`.text`, `.data` vs random names like `UPX0`)
   - Import table — very few imports often means a packer stub
   - Overlay data (extra bytes after the last section — common in file binders)

3. **Script obfuscation** — for `.vbs`, `.js`, `.ps1`, `.bat`:
   - Long single-line scripts (> 500 chars with no newlines)
   - Base64-like strings (`[A-Za-z0-9+/]{40,}={0,2}`)
   - Character-code construction (`Chr(87)&Chr(83)&...`)

4. **Scope** — run only on suspect files from SP01/SP03, not the full partition.

## Risk scoring

| Signal | Score delta |
|---|---|
| Entropy > 7.5 (likely packed/encrypted) | +35 |
| Entropy 7.2–7.5 (possibly packed) | +20 |
| PE with ≤ 2 imports (typical packer stub) | +25 |
| Non-standard PE section names | +20 |
| Overlay data present | +15 |
| Script: long single line > 500 chars | +20 |
| Script: base64 string > 100 chars | +25 |
| Normal entropy (< 6.5) | 0 |

## Output

JSONL findings to `logs/entropy_<ts>.jsonl`

## Dependencies

- Best run after SP01/SP03 to scope the input.

## Constraints

- Standard library only (struct, math, hashlib)
- Read only the first 64 KB for entropy (do not load whole file into memory)
- Read-only; never write to target volume

## Acceptance criteria

- [ ] Correctly identifies UPX-packed executables with entropy > 7.2
- [ ] Does not flag `.zip` or `.cab` files as malicious purely on entropy
- [ ] Processes 1000 files in under 60 seconds on USB hardware
