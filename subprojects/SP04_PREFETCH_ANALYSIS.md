# SP04 — PREFETCH_ANALYSIS

**Status:** 📋 Planned
**Phase:** 1 — Core scanning
**Priority:** 4

## Goal

Parse Windows Prefetch artefacts to identify recently executed programs,
including programs that have since been deleted.

## Why higher than ChatGPT's rank (#6 → #4)

Prefetch is enabled by default on Vista and is gold for execution history.
It tells you what ran, when, and how many times — even for files that no
longer exist on disk.  A deleted dropper whose Prefetch entry still names
a suspicious path is a high-confidence finding.  Pure Python, no external
dependencies.

## Scope

1. **Prefetch directory** — `C:\Windows\Prefetch\*.pf`.

2. **File format** — format version varies by OS.  Must support all versions:

   | OS | Prefetch version | Compression |
   |---|---|---|
   | XP/2003 | v17 | None |
   | Vista | v23 | None |
   | Win7 | v23 | None |
   | Win8/8.1 | v26 | MAM (XPress) |
   | Win10/11 | v30 | MAM (XPress) |

   Extract from each:
   - Executable name
   - Run count
   - Last run timestamp(s) (up to 8 timestamps in v26/v30)
   - Referenced file list (volume paths)

   **Note:** On Win10/11 with an SSD, Prefetch may be **disabled**.  Check
   `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\
   PrefetchParameters\EnablePrefetcher` — value 0 means disabled.  If
   disabled, emit an informational finding and defer to SP29 MODERN_WINDOWS_ARTEFACTS
   (Amcache) for execution history.

3. **Cross-reference** — check whether the executable referenced in each `.pf`
   file still exists on the filesystem.  A missing executable is significant.

4. **Suspicious programs** — flag prefetch entries for known LOLBins, scripting
   hosts, and installers (share the same list as SP06 LOLBIN_DETECTION).

5. **Execution clusters** — group entries by run timestamp to surface activity
   bursts.

## Risk scoring

| Signal | Score delta |
|---|---|
| Executable no longer on disk | +35 |
| Execution from Temp/AppData/Downloads | +30 |
| Known LOLBin or scripting host | +25 |
| > 10 runs total | +10 |
| Multiple runs in a short window | +10 |
| Executable in `System32` or `Program Files` | −15 |

## Notes

- MAM (XPress) decompression for Vista `.pf` files requires a pure-Python
  implementation or a fallback to `xpress_decompress` if available.
  If decompression fails, still report the file's presence and name.
- Timestamps are stored as Windows FILETIME (100-ns intervals since 1601-01-01).

## Output

JSONL findings to `logs/prefetch_<ts>.jsonl`

## Dependencies

None (standalone).

## Constraints

- Standard library only
- Read-only; never write to target volume

## Acceptance criteria

- [ ] Parses Vista format-17/23 `.pf` files without external dependencies
- [ ] Falls back gracefully if MAM decompression fails
- [ ] Reports deleted executables clearly
