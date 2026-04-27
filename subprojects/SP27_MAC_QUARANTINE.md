# SP27 — MAC_QUARANTINE

**Status:** 📋 Planned (Phase 6 — macOS expansion)
**Phase:** 6 — OS expansion
**Priority:** 27

## Goal

Inspect macOS quarantine metadata, extended attributes, and Gatekeeper-related
evidence on an offline macOS installation.

## Scope

1. **Quarantine database** — `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`
   (SQLite).  Contains a record of every file downloaded and from where.
   Parse with `sqlite3` (stdlib) if available.

2. **Extended attributes** — `com.apple.quarantine` xattr on files.  Access
   via `getfattr -n com.apple.quarantine <file>` if `attr` tools are available,
   otherwise skip with informational finding.

3. **Files that bypassed quarantine** — executables in `~/Downloads` or
   `~/Desktop` that have no quarantine xattr may have been downloaded by a
   malicious process (which wouldn't set the quarantine bit).

4. **Gatekeeper bypass indicators** — files that have been quarantine-cleared
   (`quarantine` flag with `QTNFOUserApproved` bit set) — especially for
   packages from unknown developers.

## Risk scoring

| Signal | Score delta |
|---|---|
| Executable in Downloads with no quarantine xattr | +30 |
| Quarantine record shows download from suspicious domain | +35 |
| Quarantine-cleared unsigned package | +25 |
| Apple-signed, known-good quarantine record | −10 |

## Output

JSONL findings to `logs/mac_quarantine_<ts>.jsonl`

## Dependencies

- SP24 SCAN_PROFILE_OS (macOS profile active)
- `sqlite3` stdlib module (or graceful fallback)
- `getfattr` (optional)
