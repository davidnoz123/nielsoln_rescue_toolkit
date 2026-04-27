# SP03 — SUSPICIOUS_PATHS

**Status:** 📋 Planned
**Phase:** 1 — Core scanning
**Priority:** 3

## Goal

Identify suspicious files by location, naming, type, and simple metadata —
without needing signatures or heuristic engines.

## Why here in the ordering

The highest-signal, lowest-effort scan after persistence.  A file in
`%APPDATA%\Temp` with a random 8-character name and a `.exe` extension is
suspicious regardless of its contents.  Pure Python, no dependencies, fast.

## Scope

1. **High-risk locations** — `AppData\Roaming`, `AppData\Local`, `Temp`
   directories, `Downloads`, `Desktop`, `Public`, `ProgramData`.

2. **Executable/script files** — `.exe`, `.dll`, `.scr`, `.bat`, `.cmd`,
   `.ps1`, `.vbs`, `.js`, `.hta`, `.lnk`, `.pif`, `.com` in user-writable
   locations.

3. **Double extensions** — `invoice.pdf.exe`, `photo.jpg.scr`.

4. **Random-looking names** — low character-frequency entropy in the filename
   (not file content — that is SP09).

5. **Misleading system names** — files named `svchost.exe`, `explorer.exe`,
   `lsass.exe` etc. outside their expected system locations.

6. **Recently modified files** — files in the above locations modified within a
   heuristic recency window (configurable, default 90 days).

7. **Hidden files/directories** — NTFS hidden attribute visible from `stat`
   on Linux is not reliable; use path heuristics and known hidden-folder names
   instead.

## Risk scoring

| Signal | Score delta |
|---|---|
| Executable in Temp/Downloads/AppData | +30 |
| Double extension | +25 |
| Name mimics known system binary in wrong path | +40 |
| Random-looking name (< 2 vowels in 8+ chars) | +15 |
| Modified within 30 days | +10 |
| In user-writable location | +10 |
| In `C:\Windows\System32` or `Program Files` | −20 |

## Output

JSONL findings to `logs/suspicious_paths_<ts>.jsonl`

## Dependencies

None (standalone).

## Constraints

- Standard library only
- Do not read file contents (that is SP09 ENTROPY_CHECK)
- Read-only; never write to target volume

## Acceptance criteria

- [ ] Completes scan of `Users\` tree in under 60 seconds on a 7200 RPM HDD
- [ ] Produces at least one finding on any non-fresh Windows Vista install
- [ ] No false positives on `C:\Windows\System32`
