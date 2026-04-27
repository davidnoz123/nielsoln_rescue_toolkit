# SP09 — HASH_TRACKING

**Status:** 📋 Planned
**Phase:** 2 — Engineering foundations
**Priority:** 9

## Goal

Compute and store SHA-256 hashes of suspect files to support repeat scans,
cross-machine comparison, and optional reputation lookups.

## Important scoping decision — do NOT hash everything

Vista partitions can be 80–200 GB.  Hashing all files at ~200 MB/s over USB
2.0 would take 7–17 minutes minimum and stress the old HDD.  Hash only
**suspect files** identified by other modules.

**Recommended scope (configurable):**
- All findings from SP01 (persistence targets)
- All findings from SP03 (suspicious paths)
- All findings from SP06 (LOLBin targets)
- Optionally: all `.exe`/`.dll`/`.sys` files in `System32` (for baseline comparison)

## Scope

1. **Hash computation** — SHA-256 using `hashlib` (stdlib).

2. **Hash database** — a simple JSON file on the USB:
   `logs/hash_db.json` — persistent across scans.  Schema:

   ```json
   {
     "<sha256>": {
       "first_seen": "<ts>",
       "last_seen":  "<ts>",
       "machines":   ["Garnet-PC"],
       "paths":      ["C:\\Windows\\..."],
       "scan_count": 3
     }
   }
   ```

3. **Known-bad list** — a bundled `known_bad_hashes.txt` (one SHA-256 per line)
   on the USB.  If a file matches, immediately score HIGH.  Sourced from public
   threat intel; updated via `bootstrap update`.

4. **Known-good list** — a bundled `known_good_hashes.txt` for common Vista
   system files.  If a file matches, reduce its score.

5. **Cross-machine deduplication** — if the same hash appears on a second
   client machine, that is intelligence worth noting.

## Risk scoring

| Signal | Score delta |
|---|---|
| Hash matches known-bad list | +60 |
| Hash matches known-good list | −30 |
| Hash seen on > 1 client machine | +20 |
| New hash not seen before | +0 (neutral) |

## Output

JSONL findings to `logs/hash_<ts>.jsonl`; updates `logs/hash_db.json`.

## Dependencies

- Best run after SP01/SP03/SP06 to scope the input file list.

## Constraints

- Standard library only (hashlib, json)
- Read-only on target volume; writes only to USB log directory
- Must handle large files without loading them fully into memory

## Acceptance criteria

- [ ] Hashes only files in the configured scope (not the full partition)
- [ ] Persists hash DB across scans
- [ ] Matches against bundled known-bad list
- [ ] Handles permission errors and large files gracefully
