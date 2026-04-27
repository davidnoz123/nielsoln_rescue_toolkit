# SP12 — RECENT_ACTIVITY

**Status:** 📋 Planned
**Phase:** 3 — Deeper forensics
**Priority:** 12

## Goal

Find clusters of recent filesystem activity that may indicate infection events,
dropper activity, or post-compromise file placement.

## Scope

1. **Filesystem walk** — scan key directories for files modified within a
   configurable recency window (default: 90 days before last-seen boot date
   from SP02, or current date if not available).

   Directories to prioritise:
   - All user `AppData\`, `Desktop\`, `Downloads\`, `Documents\`
   - `C:\Windows\Temp\`, `C:\Temp\`
   - `C:\ProgramData\`
   - `C:\Windows\System32\` (for new DLLs or executables)
   - `C:\Windows\SysWOW64\` if present

2. **Activity clustering** — group modified files by time window (1-hour
   buckets) to identify bursts.  A cluster of 10+ new files in one hour
   in AppData is suspicious.

3. **New executables** — any `.exe`, `.dll`, `.sys`, `.scr` modified in the
   recency window and located outside `C:\Windows\` or `C:\Program Files\`.

4. **Correlation with SP01** — cross-reference recently modified files against
   persistence findings; a persistence entry pointing to a recently dropped file
   is a strong signal.

## Risk scoring

| Signal | Score delta |
|---|---|
| Executable dropped in Temp/AppData recently | +35 |
| Cluster of > 10 files in 1 hour in user dirs | +25 |
| New file in `System32` (not Windows Update) | +30 |
| File modified after last known user login | +20 |
| File in known-safe directory, no cluster | 0 |

## Output

JSONL findings to `logs/recent_activity_<ts>.jsonl`

## Dependencies

- SP02 DISK_OVERVIEW (for last-boot/last-login hints)
- SP01 PERSISTENCE_SCAN JSONL (for cross-reference)

## Constraints

- Standard library only
- Read-only; never write to target volume

## Acceptance criteria

- [ ] Detects a cluster of files dropped in AppData within a 1-hour window
- [ ] Does not flag Windows Update installers in `System32` as suspicious
- [ ] Completes in under 2 minutes on a 100 GB partition
