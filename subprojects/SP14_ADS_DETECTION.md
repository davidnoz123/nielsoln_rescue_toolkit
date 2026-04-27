# SP14 — ADS_DETECTION

**Status:** ⚠️ Flagged — Linux kernel / mount dependency
**Phase:** 3 — Deeper forensics
**Priority:** 14

## Goal

Detect NTFS Alternate Data Streams (ADS) that may be used to hide payloads,
scripts, or malware in plain sight on the filesystem.

## Constraint flag

ADS access from Linux requires kernel-level NTFS support.  The `ntfs-3g`
userspace driver **does not** expose ADS through the standard POSIX filesystem
interface.  Access requires one of:

- `getfattr -n ntfs.streams.list <file>` — if `attr` package is installed
- Direct reading via `ntfs-3g` extended attributes (`user.stream:...`)
- `ntfscat` from the `ntfs-3g` tools package
- Raw NTFS parsing (complex, out of scope for stdlib-only Python)

**Recommendation:** implement a best-effort approach:
1. Try `getfattr` or `ntfscat` via `subprocess`.
2. If neither is available, emit an informational finding explaining the
   limitation and skip ADS scanning.
3. Do not require these tools — graceful degradation is mandatory.

RescueZilla ships `ntfs-3g` but the `attr` package may not be present.
Check at runtime.

## Scope (if tools are available)

1. **Scan target directories** — same high-risk locations as SP03.
2. **List ADS per file** — extract stream names and sizes.
3. **Flag suspicious streams:**
   - Non-standard stream names (anything other than `:$DATA`, `:Zone.Identifier`)
   - Streams on executables
   - Large streams (> 1 KB) on non-data files
   - Executable content in streams (check first bytes for MZ header)

## Risk scoring

| Signal | Score delta |
|---|---|
| ADS with MZ/PE header | +55 |
| ADS with script content | +40 |
| ADS larger than 1 KB on a non-data file | +25 |
| `Zone.Identifier` stream (normal, downloaded file mark) | −5 |

## Output

JSONL findings to `logs/ads_<ts>.jsonl`; informational finding if tool
unavailable.

## Dependencies

- External: `getfattr` or `ntfscat` (runtime check, optional)

## Acceptance criteria

- [ ] Emits an informational finding if no ADS tools are available
- [ ] Does not crash if `getfattr` is absent
- [ ] Correctly identifies a manually created test ADS stream
