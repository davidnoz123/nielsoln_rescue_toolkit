# SP16 — MEMORY_ARTEFACTS

**Status:** 📋 Planned (limited scope in offline context)
**Phase:** 3 — Deeper forensics
**Priority:** 16

## Goal

Detect offline evidence of memory-related files that may contain forensic
artefacts, or indicate system instability caused by malware.

## Scope limitation

True memory forensics (live process inspection, heap analysis) is not possible
offline.  The scope here is limited to:

1. **Hibernation file** — `C:\hiberfil.sys`:
   - Presence and size (a very small file suggests the system has been
     partially resumed/restored)
   - Does not parse the Hibernation file format (requires complex decompression)
   - Just report its presence, size, and last-modified timestamp

2. **Page file** — `C:\pagefile.sys`:
   - Presence and size
   - Scan the first 1 MB for printable string artefacts (URLs, email addresses,
     registry paths, base64 blobs) using simple regex — no full parsing

3. **Crash dumps** — `C:\Windows\Minidump\*.dmp` and
   `C:\Windows\MEMORY.DMP`:
   - Presence, count, and dates
   - Repeated crashes (many minidumps) indicate malware or rootkit activity
   - Report the bugcheck code from the minidump header (simple struct parse)

4. **System Error Log** — cross-reference with SP07 event logs for BSOD events
   if available

## Risk scoring

| Signal | Score delta |
|---|---|
| > 3 minidumps in last 90 days | +20 |
| > 10 minidumps total | +30 |
| `pagefile.sys` string scan: suspicious URL or path | +25 |
| Pagefile much smaller than RAM hints (< 1 GB on > 2 GB machine) | +10 |

## Output

JSONL findings to `logs/memory_artefacts_<ts>.jsonl`

## Dependencies

- SP02 DISK_OVERVIEW (for RAM size hint from registry)
- SP07 WINDOWS_EVENT_LOGS (for BSOD event correlation, optional)

## Constraints

- Standard library only
- Never load more than 1 MB of pagefile into memory at once

## Acceptance criteria

- [ ] Reports minidump count and most recent date
- [ ] Scans first 1 MB of pagefile for suspicious strings without crashing
- [ ] Does not attempt to parse the full hibernation file
