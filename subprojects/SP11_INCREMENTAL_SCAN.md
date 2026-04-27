# SP11 — INCREMENTAL_SCAN

**Status:** 📋 Planned
**Phase:** 2 — Engineering foundations
**Priority:** 11

## Goal

Skip unchanged files on repeat scans by caching file metadata and hashes,
so subsequent runs on the same machine are significantly faster.

## Scope

1. **Scan state cache** — `logs/scan_state.json` on the USB.  Stores per-file:
   - Absolute path
   - `st_mtime`, `st_size`, `st_ino`
   - SHA-256 (if previously hashed by SP09)
   - Last scan timestamp

2. **Cache invalidation** — a file is considered changed if `st_mtime` or
   `st_size` has changed.  A changed file is always re-scanned.

3. **Integration** — each scan module queries the cache before processing a
   file.  If the file is unchanged since the last scan, the previous findings
   are carried forward with a `"cached": true` flag.

4. **Force-refresh flag** — `bootstrap scan --force` bypasses the cache.

5. **Cache pruning** — entries for paths that no longer exist are removed after
   a full scan.

## Notes

- The cache lives on the USB (writable), not on the target volume (read-only).
- On Vista NTFS, `st_mtime` may not always be reliable due to lazy metadata
  writes.  Use both `st_mtime` and `st_size` together.
- The first scan on a machine will always be a full scan.

## Output

Updates `logs/scan_state.json`.  No JSONL findings of its own.

## Dependencies

- SP09 HASH_TRACKING (to populate the hash cache)
- SP08 RISK_SCORING / core.py (to carry forward cached findings)

## Constraints

- Standard library only (json, os.stat)
- Never write to target volume

## Acceptance criteria

- [ ] Second scan on an unchanged machine is at least 5× faster than first
- [ ] Changed files are always re-scanned
- [ ] `--force` flag bypasses cache completely
