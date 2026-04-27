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

2. **File format** — Windows Vista uses Prefetch format version 17 (MAM
   compressed) or 23.  Parse the header to extract:
   - Executable name
   - Run count
   - Last run timestamp(s)
   - Referenced file list (volume paths)

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
